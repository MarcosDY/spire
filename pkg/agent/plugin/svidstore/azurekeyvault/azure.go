package azurekeyvault

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "azure_keyvault"
)

type secret struct {
	name     string
	keyvault string
	location string
	group    string
	tenantID string
}

func (s *secret) vaultBaseURL() string {
	return fmt.Sprintf("https://%s.%s/", s.name, azure.PublicCloud.KeyVaultDNSSuffix)
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *KeyVaultPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		svidstorev1.SVIDStorePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *KeyVaultPlugin {
	return &KeyVaultPlugin{}
}

type Config struct {
	Location       string `hcl:"location" json:"location"`
	ResourceGroup  string `hcl:"resource_group" json:"resource_group"`
	SubscriptionID string `hcl:"subscription_id" json:"subscription_id"`
	TenantID       string `hcl:"tenant_id" json:"tenant_id"`
}

type KeyVaultPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log    hclog.Logger
	config *Config
	mtx    sync.RWMutex

	mgmtVaultClient    mgmtVaultClient
	serviceVaultClient serviceClientVault
	td                 string
	hooks              struct {
		createMgmtVaultClient    func(string) (mgmtVaultClient, error)
		createServiceVaultClient func() (serviceClientVault, error)
	}
}

func (p *KeyVaultPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the KeyVaultPlugin.
func (p *KeyVaultPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.SubscriptionID == "" {
		return nil, status.Error(codes.InvalidArgument, "subscription ID is required")
	}

	mgmtVaultClient, err := p.hooks.createMgmtVaultClient(config.SubscriptionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create management vault client: %v", err)
	}

	serviceVaultClient, err := p.hooks.createServiceVaultClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create service vault client: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config
	p.mgmtVaultClient = mgmtVaultClient
	p.serviceVaultClient = serviceVaultClient
	p.td = req.CoreConfiguration.TrustDomain

	return &configv1.ConfigureResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Azure Key Vault
func (p *KeyVaultPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	s, err := p.parseSelectors(req.Metadata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid metadata: %v", err)
	}

	// response contains datails about `error` when call fails.
	keyVault, err := p.mgmtVaultClient.Get(ctx, s.group, s.keyvault)
	switch keyVault.StatusCode {
	case http.StatusOK:
		p.log.With("vault", keyVault.Name).Debug("key vault found")
		if !validateTag(keyVault.Tags, p.td) {
			return nil, status.Errorf(codes.InvalidArgument, "key vault %q does not contains 'spire-svid' tag", s.keyvault)
		}

	case http.StatusNotFound:
		p.log.With("vault", s.keyvault).Debug("key vault not found, creating...")
		if err := p.createKeyVault(ctx, s); err != nil {
			return nil, err
		}

	default:
		return nil, status.Errorf(codes.Internal, "failed to get key vault %q: %v", s.keyvault, err)
	}

	// Add new secret to Key Vault
	if err := p.setSecret(ctx, req, s); err != nil {
		return nil, err
	}

	return &svidstorev1.PutX509SVIDResponse{}, nil
}

func (p *KeyVaultPlugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	s, err := p.parseSelectors(req.Metadata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid metadata: %v", err)
	}

	// response contains datails about `error` when call fails.
	keyVault, err := p.mgmtVaultClient.Get(ctx, s.group, s.keyvault)
	switch keyVault.StatusCode {
	case http.StatusOK:
		p.log.With("vault", keyVault.Name).Debug("key vault found")
		if !validateTag(keyVault.Tags, p.td) {
			return nil, status.Errorf(codes.InvalidArgument, "key vault %q does not contains 'spire-svid' tag", s.keyvault)
		}

	case http.StatusNotFound:
		p.log.With("vault", s.keyvault).Debug("key vault not found")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil

	default:
		return nil, status.Errorf(codes.Internal, "failed to get key vault %q: %v", s.keyvault, err)
	}

	vaultBaseURL := s.vaultBaseURL()
	// Get only 2 secrets we want to verify it contains more than 1
	secrets, err := p.serviceVaultClient.GetSecrets(ctx, vaultBaseURL, to.Int32Ptr(2))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get secrets for key vault: %v", err)
	}

	if len(secrets.Values()) <= 1 {
		if _, err := p.mgmtVaultClient.Delete(ctx, s.group, s.keyvault); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to delete key vault: %v", err)
		}

		p.log.With("id", keyVault.ID).Debug("Key vault deleted")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil
	}

	resp, err := p.serviceVaultClient.DeleteSecret(ctx, vaultBaseURL, s.name)
	switch resp.StatusCode {
	case http.StatusOK:
		p.log.With("id", resp.ID).Debug("Secret deleted")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil

	case http.StatusNotFound:
		p.log.With("secret", s.name).Debug("Secret already deleted")
		return &svidstorev1.DeleteX509SVIDResponse{}, nil

	default:
		return nil, status.Errorf(codes.Internal, "failed to delete secret: %v", err)
	}
}

// setSecret adds a new SVID as a secret an specified Key Vault
func (p *KeyVaultPlugin) setSecret(ctx context.Context, req *svidstorev1.PutX509SVIDRequest, s *secret) error {
	data, err := svidstore.SecretFromProto(req)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to encode sercret: %v", err)
	}

	secretBinary, err := json.Marshal(data)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal SVID: %v", err)
	}

	cert, err := x509.ParseCertificate(req.Svid.CertChain[0])
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse SVID certificate: %v", err)
	}

	notBefore := date.NewUnixTimeFromNanoseconds(cert.NotBefore.UnixNano())
	expires := date.NewUnixTimeFromNanoseconds(cert.NotAfter.UnixNano())

	// TODO: add var for vautl name and another for secret name
	resp, err := p.serviceVaultClient.SetSecret(ctx, s.vaultBaseURL(), s.name, kv.SecretSetParameters{
		Value:       to.StringPtr(string(secretBinary)),
		ContentType: to.StringPtr("X509-SVID"),
		SecretAttributes: &kv.SecretAttributes{
			NotBefore: &notBefore,
			Expires:   &expires,
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to set secret: %v", err)
	}

	p.log.With("id", resp.ID).Info("Secret updated")

	return nil
}

// createKeyVault verify if Key Vault exists and it contains 'spire-svid' tag.
// If not exists a new Key Vault is created
func (p *KeyVaultPlugin) createKeyVault(ctx context.Context, s *secret) error {
	if s.location == "" {
		return status.Error(codes.InvalidArgument, "location is required to create key vault")
	}

	tenantID, err := uuid.FromString(s.tenantID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "malformed tenant ID: %v", err)
	}

	// Get current user ID, it is required to create an access policy to allow current user to  get and set secrets.
	userID, err := p.getCurrentUser(ctx, s.tenantID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get current user: %v", err)
	}

	properties := &keyvault.VaultProperties{
		TenantID: &tenantID,
		Sku: &keyvault.Sku{
			Family: to.StringPtr("A"),
			Name:   keyvault.Standard,
		},
		// Used to set permissions
		// TODO: may we add more selectors in order to add more User and Tenants?
		AccessPolicies: &[]keyvault.AccessPolicyEntry{
			{
				ObjectID: userID,
				TenantID: &tenantID,
				Permissions: &keyvault.Permissions{
					Secrets: &[]keyvault.SecretPermissions{
						// Get and List are not required, added them to verify they exists on UI
						keyvault.SecretPermissionsGet,
						keyvault.SecretPermissionsSet,
						keyvault.SecretPermissionsList,
					},
				},
			},
		},
	}

	_, err = p.mgmtVaultClient.CreateOrUpdate(ctx, s.group, s.keyvault, keyvault.VaultCreateOrUpdateParameters{
		Location:   &s.location,
		Tags:       map[string]*string{"spire-svid": to.StringPtr(p.td)},
		Properties: properties,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	return nil
}

// getCurrentUser gets current user ID.
func (p *KeyVaultPlugin) getCurrentUser(ctx context.Context, tenantID string) (*string, error) {
	client, err := createSignedInUserClient(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Auth: %w", err)
	}

	user, err := client.Get(ctx)
	if err != nil {
		return nil, err
	}

	return user.ObjectID, nil
}

// parseSelectors parse selectors into 'secret', and set default values if required
func (p *KeyVaultPlugin) parseSelectors(metadata []string) (*secret, error) {
	data, err := svidstore.ParseMetadata(metadata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse metadata: %v", err)
	}

	name, ok := data["secretname"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "secret name is required")
	}

	vault, ok := data["secretvault"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "secret vault is required")
	}

	group := p.config.ResourceGroup
	if value, ok := data["secretgroup"]; ok {
		group = value
	}
	if group == "" {
		return nil, status.Error(codes.InvalidArgument, "secret group name is required")
	}

	tenantID := p.config.TenantID
	if value, ok := data["secrettenantid"]; ok {
		tenantID = value
	}
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "secret tenant ID is required")
	}

	location := p.config.Location
	if value, ok := data["secretlocation"]; ok {
		location = value
	}

	return &secret{
		name:     name,
		group:    group,
		location: location,
		tenantID: tenantID,
		keyvault: vault,
	}, nil
}

// validateTag validates that tags contains 'spire-svid' and it is 'true'
func validateTag(tags map[string]*string, td string) bool {
	spireLabel, ok := tags["spire-svid"]
	return ok && to.String(spireLabel) == td
}
