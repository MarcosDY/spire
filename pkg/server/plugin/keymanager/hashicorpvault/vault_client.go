package hashicorpvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire/pkg/common/backoff"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

const (
	envVaultAddr              = "VAULT_ADDR"
	envVaultToken             = "VAULT_TOKEN"
	envVaultClientCert        = "VAULT_CLIENT_CERT"
	envVaultClientKey         = "VAULT_CLIENT_KEY"
	envVaultCACert            = "VAULT_CACERT"
	envVaultAppRoleID         = "VAULT_APPROLE_ID"
	envVaultAppRoleSecretID   = "VAULT_APPROLE_SECRET_ID" // #nosec G101
	envVaultNamespace         = "VAULT_NAMESPACE"
	envVaultTransitEnginePath = "VAULT_TRANSIT_ENGINE_PATH"

	defaultCertMountPoint    = "cert"
	defaultPKIMountPoint     = "pki"
	defaultTransitEnginePath = "transit"
	defaultAppRoleMountPoint = "approle"
	defaultK8sMountPoint     = "kubernetes"
)

var (
	bootstrapBackoffInterval       = 5 * time.Second
	bootstrapBackoffMaxElapsedTime = 1 * time.Minute

	vaultClientNotInitializedError = status.Error(codes.Internal, "vault client is not initialized")
)

type AuthMethod int

const (
	_ AuthMethod = iota
	CERT
	TOKEN
	APPROLE
	K8S
)

// ClientConfig represents configuration parameters for vault client
type ClientConfig struct {
	Logger hclog.Logger
	// vault client parameters
	clientParams *ClientParams
	clk          clock.Clock
}

type ClientParams struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string
	// Name of mount point where PKI secret engine is mounted. (e.e., /<mount_point>/ca/pem )
	PKIMountPoint string
	// token string to use when auth method is 'token'
	Token string
	// Name of mount point where TLS Cert auth method is mounted. (e.g., /auth/<mount_point>/login )
	CertAuthMountPoint string
	// Name of the Vault role.
	// If given, the plugin authenticates against only the named role
	CertAuthRoleName string
	// Path to a client certificate file to be used when auth method is 'cert'
	ClientCertPath string
	// Path to a client private key file to be used when auth method is 'cert'
	ClientKeyPath string
	// Path to a CA certificate file to be used when client verifies a server certificate
	CACertPath string
	// Name of mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login )
	AppRoleAuthMountPoint string
	// An identifier of AppRole
	AppRoleID string
	// A credential set of AppRole
	AppRoleSecretID string
	// Name of the mount point where Kubernetes auth method is mounted. (e.g., /auth/<mount_point>/login)
	K8sAuthMountPoint string
	// Name of the Vault role.
	// The plugin authenticates against the named role.
	K8sAuthRoleName string
	// Path to a K8s Service Account Token to be used when auth method is 'k8s'
	K8sAuthTokenPath string
	// If true, client accepts any certificates.
	// It should be used only test environment so on.
	TLSSKipVerify bool
	// MaxRetries controls the number of times to retry to connect
	// Set to 0 to disable retrying.
	// If the value is nil, to use the default in hashicorp/vault/api.
	MaxRetries *int
	// Name of the Vault namespace
	Namespace string
	// TransitEnginePath specifies the path to the transit engine to perform key operations.
	TransitEnginePath string
}

// NewClientConfig returns a new *ClientConfig with default parameters.
func NewClientConfig(cp *ClientParams, logger hclog.Logger) (*ClientConfig, error) {
	cc := &ClientConfig{
		Logger: logger,
		clk:    clock.New(),
	}
	defaultParams := &ClientParams{
		CertAuthMountPoint:    defaultCertMountPoint,
		AppRoleAuthMountPoint: defaultAppRoleMountPoint,
		K8sAuthMountPoint:     defaultK8sMountPoint,
		PKIMountPoint:         defaultPKIMountPoint,
		TransitEnginePath:     defaultTransitEnginePath,
	}
	if err := mergo.Merge(cp, defaultParams); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to merge client params: %v", err)
	}
	cc.clientParams = cp
	return cc, nil
}

// NewAuthenticatedClient returns a new authenticated vault client with given authentication method
func (c *ClientConfig) NewAuthenticatedClient(ctx context.Context, method AuthMethod) (client *Client, err error) {
	client = &Client{}

	err = c.completeClient(client, method)
	if err != nil {
		return nil, err
	}

	if client.secret.Auth.LeaseDuration == 0 {
		c.Logger.Debug("Token will never expire")
		return client, nil
	}

	if !client.secret.Auth.Renewable {
		c.Logger.Debug("Token is not renewable")
		return client, nil
	}

	client.renewable = true
	go func() {
		err := c.handleRenewToken(ctx, client, method)
		if err != nil && !errors.Is(err, context.Canceled) {
			// This must never happens, but just in case log the error to help debugging.
			c.Logger.Error("error handling token renewal", err)
			client.setClient(nil) // to indicate that client is no longer valid,
		}
	}()

	return client, nil
}

func (c *ClientConfig) handleRenewToken(ctx context.Context, client *Client, method AuthMethod) error {
	initBackoff := backoff.NewBackoff(c.clk, bootstrapBackoffInterval, backoff.WithMaxElapsedTime(bootstrapBackoffMaxElapsedTime))

	for {
		renew, err := NewRenew(client.getClient(), client.secret, c.Logger)
		if err != nil {
			c.Logger.Error("unable to create renew", err)
		}

		if renew != nil {
			// Renew finalized without error finalize routine
			err = renew.Run(ctx)
			if err == nil || errors.Is(err, context.Canceled) {
				return nil
			}
			c.Logger.Error("token renewal failed, re-authenticating", err)
			if client.hooks.renewCh != nil {
				client.hooks.renewCh <- err
			}
		}

		// Create a new client and re-authenticate
		if err := c.completeClient(client, method); err != nil {
			c.Logger.Error("unable to re-authenticate client", err)
			return err
		}

		// Backoff before retrying
		nextDuration := initBackoff.NextBackOff()
		if nextDuration == backoff.Stop {
			c.Logger.Error("backoff reached stop condition, giving up")
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-c.clk.After(nextDuration):
		}
	}
}

func (c *ClientConfig) completeClient(client *Client, method AuthMethod) error {
	config := vapi.DefaultConfig()
	config.Address = c.clientParams.VaultAddr
	if c.clientParams.MaxRetries != nil {
		config.MaxRetries = *c.clientParams.MaxRetries
	}

	if err := c.configureTLS(config); err != nil {
		return err
	}
	vc, err := vapi.NewClient(config)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create Vault client: %v", err)
	}

	if c.clientParams.Namespace != "" {
		vc.SetNamespace(c.clientParams.Namespace)
	}

	client.initializeClient(vc, c.clientParams)

	sec, err := c.lookupSecret(client, method)
	if err != nil {
		return err
	}

	if sec == nil || sec.Auth == nil {
		return status.Error(codes.InvalidArgument, "secret is nil")
	}

	client.setSecret(sec)

	return nil
}

func (c *ClientConfig) lookupSecret(client *Client, method AuthMethod) (*vapi.Secret, error) {
	switch method {
	case TOKEN:
		sec, err := client.LookupSelf(c.clientParams.Token)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "lookup self response is nil")
		}
		return sec, nil

	case CERT:
		path := fmt.Sprintf("auth/%v/login", c.clientParams.CertAuthMountPoint)
		sec, err := client.Auth(path, map[string]any{
			"name": c.clientParams.CertAuthRoleName,
		})
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "tls cert authentication response is nil")
		}
		return sec, nil

	case APPROLE:
		path := fmt.Sprintf("auth/%v/login", c.clientParams.AppRoleAuthMountPoint)
		body := map[string]any{
			"role_id":   c.clientParams.AppRoleID,
			"secret_id": c.clientParams.AppRoleSecretID,
		}
		sec, err := client.Auth(path, body)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "approle authentication response is nil")
		}
		return sec, nil

	case K8S:
		b, err := os.ReadFile(c.clientParams.K8sAuthTokenPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read k8s service account token: %v", err)
		}
		path := fmt.Sprintf("auth/%s/login", c.clientParams.K8sAuthMountPoint)
		body := map[string]any{
			"role": c.clientParams.K8sAuthRoleName,
			"jwt":  string(b),
		}
		sec, err := client.Auth(path, body)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, status.Error(codes.Internal, "k8s authentication response is nil")
		}
		return sec, nil

	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported auth method")
	}
}

// ConfigureTLS Configures TLS for Vault Client
func (c *ClientConfig) configureTLS(vc *vapi.Config) error {
	if vc.HttpClient == nil {
		vc.HttpClient = vapi.DefaultConfig().HttpClient
	}

	transport, ok := vc.HttpClient.Transport.(*http.Transport)
	if !ok {
		return status.Errorf(codes.Internal, "http client transport is of incorrect type. Expected is %T but was %T", transport, vc.HttpClient.Transport)
	}

	clientTLSConfig := transport.TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case c.clientParams.ClientCertPath != "" && c.clientParams.ClientKeyPath != "":
		var err error

		clientCert, err = tls.LoadX509KeyPair(c.clientParams.ClientCertPath, c.clientParams.ClientKeyPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to parse client cert and private-key: %v", err)
		}
		foundClientCert = true
	case c.clientParams.ClientCertPath != "" || c.clientParams.ClientKeyPath != "":
		return status.Error(codes.InvalidArgument, "both client cert and client key are required")
	}

	if c.clientParams.CACertPath != "" {
		certs, err := pemutil.LoadCertificates(c.clientParams.CACertPath)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "failed to load CA certificate: %v", err)
		}
		pool := x509.NewCertPool()
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		clientTLSConfig.RootCAs = pool
	}

	if c.clientParams.TLSSKipVerify {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	return nil
}

type Client struct {
	vaultClient  *vapi.Client
	clientParams *ClientParams
	secret       *vapi.Secret

	renewable bool
	mtx       sync.RWMutex

	// For testing only
	hooks struct {
		renewCh chan error
	}
}

// SetToken wraps vapi.Client.SetToken()
func (c *Client) SetToken(v string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.vaultClient.SetToken(v)
}

// Auth authenticates to vault server with TLS certificate method
func (c *Client) Auth(path string, body map[string]any) (*vapi.Secret, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.vaultClient.ClearToken()
	secret, err := c.vaultClient.Logical().Write(path, body)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed %v: %v", path, err)
	}

	tokenID, err := secret.TokenID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authentication is successful, but could not get token: %v", err)
	}
	c.vaultClient.SetToken(tokenID)
	return secret, nil
}

func (c *Client) LookupSelf(token string) (*vapi.Secret, error) {
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is empty")
	}
	c.SetToken(token)

	c.mtx.RLock()
	defer c.mtx.RUnlock()

	secret, err := c.vaultClient.Logical().Read("auth/token/lookup-self")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token lookup failed: %v", err)
	}

	id, err := secret.TokenID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get TokenID: %v", err)
	}
	renewable, err := secret.TokenIsRenewable()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to determine if token is renewable: %v", err)
	}
	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get token ttl: %v", err)
	}
	secret.Auth = &vapi.SecretAuth{
		ClientToken:   id,
		Renewable:     renewable,
		LeaseDuration: int(ttl.Seconds()),
		// other parameters are not relevant for token renewal
	}
	return secret, nil
}

func (c *Client) setClient(vaultClient *vapi.Client) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.vaultClient = vaultClient
}

func (c *Client) initializeClient(vaultClient *vapi.Client, params *ClientParams) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.vaultClient = vaultClient
	c.clientParams = params
}

func (c *Client) setSecret(secret *vapi.Secret) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.secret = secret
}

func (c *Client) getClient() *vapi.Client {
	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.vaultClient
}

type TransitKeyType string

const (
	TransitKeyTypeRSA2048   TransitKeyType = "rsa-2048"
	TransitKeyTypeRSA4096   TransitKeyType = "rsa-4096"
	TransitKeyTypeECDSAP256 TransitKeyType = "ecdsa-p256"
	TransitKeyTypeECDSAP384 TransitKeyType = "ecdsa-p384"
)

type TransitHashAlgorithm string

const (
	TransitHashAlgorithmSHA256 TransitHashAlgorithm = "sha2-256"
	TransitHashAlgorithmSHA384 TransitHashAlgorithm = "sha2-384"
	TransitHashAlgorithmSHA512 TransitHashAlgorithm = "sha2-512"
	TransitHashAlgorithmNone   TransitHashAlgorithm = "none"
)

type TransitSignatureAlgorithm string

const (
	TransitSignatureSignatureAlgorithmPSS      TransitSignatureAlgorithm = "pss"
	TransitSignatureSignatureAlgorithmPKCS1v15 TransitSignatureAlgorithm = "pkcs1v15"
)

// CreateKey creates a new key in the specified transit secret engine
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key
func (c *Client) CreateKey(ctx context.Context, keyName string, keyType TransitKeyType) error {
	if c.vaultClient == nil {
		return vaultClientNotInitializedError
	}
	arguments := map[string]any{
		"type":       keyType,
		"exportable": "false", // SPIRE keys are never exportable
	}

	_, err := c.vaultClient.Logical().WriteWithContext(ctx, fmt.Sprintf("/%s/keys/%s", c.clientParams.TransitEnginePath, keyName), arguments)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create transit engine key: %v", err)
	}

	return nil
}

// DeleteKey deletes a key in the specified transit secret engine
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#update-key-configuration and https://developer.hashicorp.com/vault/api-docs/secret/transit#delete-key
func (c *Client) DeleteKey(ctx context.Context, keyName string) error {
	if c.vaultClient == nil {
		return vaultClientNotInitializedError
	}

	arguments := map[string]any{
		"deletion_allowed": "true",
	}

	// First, we need to enable deletion of the key. This is disabled by default.
	_, err := c.vaultClient.Logical().WriteWithContext(ctx, fmt.Sprintf("/%s/keys/%s/config", c.clientParams.TransitEnginePath, keyName), arguments)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to enable deletion of transit engine key: %v", err)
	}

	_, err = c.vaultClient.Logical().DeleteWithContext(ctx, fmt.Sprintf("/%s/keys/%s", c.clientParams.TransitEnginePath, keyName))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to delete transit engine key: %v", err)
	}

	return nil
}

// SignData signs the data using the transit engine key with the key name.
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data
func (c *Client) SignData(ctx context.Context, keyName string, data []byte, hashAlgo TransitHashAlgorithm, signatureAlgo TransitSignatureAlgorithm) ([]byte, error) {
	if c.vaultClient == nil {
		return nil, vaultClientNotInitializedError
	}

	encodedData := base64.StdEncoding.EncodeToString(data)

	body := map[string]any{
		"input":                 encodedData,
		"signature_algorithm":   signatureAlgo,
		"marshalling_algorithm": "asn1",
		"prehashed":             "true",
	}

	sigResp, err := c.vaultClient.Logical().WriteWithContext(ctx, fmt.Sprintf("/%s/sign/%s/%s", c.clientParams.TransitEnginePath, keyName, hashAlgo), body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "transit engine sign call failed: %v", err)
	}

	sig, ok := sigResp.Data["signature"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine sign call was successful but signature is missing")
	}

	sigStr, ok := sig.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected signature data type %T but got %T", sigStr, sig)
	}

	// Vault adds an application specific prefix that we need to remove
	cutSig, ok := strings.CutPrefix(sigStr, "vault:v1:")
	if !ok {
		return nil, status.Errorf(codes.Internal, "signature is missing vault prefix: %v", err)
	}

	sigData, err := base64.StdEncoding.DecodeString(cutSig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to base64 decode signature: %v", err)
	}

	return sigData, nil
}

// GetKeys returns all the keys of the transit engine.
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#list-keys
func (c *Client) GetKeys(ctx context.Context) ([]*keyEntry, error) {
	if c.vaultClient == nil {
		return nil, vaultClientNotInitializedError
	}

	var keyEntries []*keyEntry

	listResp, err := c.vaultClient.Logical().ListWithContext(ctx, fmt.Sprintf("/%s/keys", c.clientParams.TransitEnginePath))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "transit engine list keys call failed: %v", err)
	}

	if listResp == nil {
		return []*keyEntry{}, nil
	}

	keys, ok := listResp.Data["keys"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine list keys call was successful but keys are missing")
	}

	keyNames, ok := keys.([]any)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected keys data type %T but got %T", keyNames, keys)
	}

	for _, keyName := range keyNames {
		keyNameStr, ok := keyName.(string)
		if !ok {
			return nil, status.Errorf(codes.Internal, "expected key id data type %T but got %T", keyNameStr, keyName)
		}

		keyEntry, err := c.getKeyEntry(ctx, keyNameStr)
		if err != nil {
			return nil, err
		}

		keyEntries = append(keyEntries, keyEntry)
	}

	return keyEntries, nil
}

// getKeyEntry gets the transit engine key with the specified key name and converts it into a key entry.
func (c *Client) getKeyEntry(ctx context.Context, keyName string) (*keyEntry, error) {
	spireKeyID, ok := spireKeyIDFromKeyName(keyName)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to get SPIRE key ID from key %s", keyName)
	}

	keyData, err := c.getKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	pk, ok := keyData["public_key"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected public key to be present")
	}

	pkStr, ok := pk.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected public key data type %T but got %T", pkStr, pk)
	}

	pemBlock, _ := pem.Decode([]byte(pkStr))
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, status.Error(codes.Internal, "unable to decode PEM key")
	}

	pubKeyType, ok := keyData["name"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected name to be present")
	}

	pubKeyTypeStr, ok := pubKeyType.(string)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected public key type to be of type %T but got %T", pubKeyTypeStr, pubKeyType)
	}

	var keyType keymanagerv1.KeyType

	switch pubKeyTypeStr {
	case "P-256":
		keyType = keymanagerv1.KeyType_EC_P256
	case "P-384":
		keyType = keymanagerv1.KeyType_EC_P384
	case "rsa-2048":
		keyType = keymanagerv1.KeyType_RSA_2048
	case "rsa-4096":
		keyType = keymanagerv1.KeyType_RSA_4096
	default:
		return nil, status.Errorf(codes.Internal, "unsupported key type: %v", pubKeyTypeStr)
	}

	return &keyEntry{
		KeyName: keyName,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          spireKeyID,
			Type:        keyType,
			PkixData:    pemBlock.Bytes,
			Fingerprint: makeFingerprint(pemBlock.Bytes),
		},
	}, nil
}

// getKey returns a specific key from the transit engine.
// See: https://developer.hashicorp.com/vault/api-docs/secret/transit#read-key
func (c *Client) getKey(ctx context.Context, keyName string) (map[string]any, error) {
	res, err := c.vaultClient.Logical().ReadWithContext(ctx, fmt.Sprintf("/%s/keys/%s", c.clientParams.TransitEnginePath, keyName))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get transit engine key: %v", err)
	}

	keys, ok := res.Data["keys"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "transit engine get key call was successful but keys are missing")
	}

	keyMap, ok := keys.(map[string]any)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected key map data type %T but got %T", keyMap, keys)
	}

	currentKey, ok := keyMap["1"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to find key with version 1 in %v", keyMap)
	}

	currentKeyMap, ok := currentKey.(map[string]any)
	if !ok {
		return nil, status.Errorf(codes.Internal, "expected key data type %T but got %T", currentKeyMap, currentKey)
	}

	return currentKeyMap, nil
}

// spireKeyIDFromKeyName parses a Key Vault key name to get the
// SPIRE Key ID. This Key ID is used in the Server KeyManager interface.
func spireKeyIDFromKeyName(keyName string) (string, bool) {
	// A key name would have the format <UUID>-<SPIRE-KEY-ID>.
	// first we find the position where the SPIRE Key ID starts.
	spireKeyIDIndex := 37 // 36 is the UUID length plus one '-' separator
	if spireKeyIDIndex >= len(keyName) {
		// The index is out of range.
		return "", false
	}
	spireKeyID := keyName[spireKeyIDIndex:]
	return spireKeyID, true
}
