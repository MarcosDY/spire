package azurekeyvault

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	x509CertPem = `-----BEGIN CERTIFICATE-----
MIICcDCCAdKgAwIBAgIBAjAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UEChMGU1BJRkZFMB4XDTE4MDIxMDAwMzY1NVoXDTE4MDIxMDAxMzY1NlowHTEL
MAkGA1UEBhMCVVMxDjAMBgNVBAoTBVNQSVJFMIGbMBAGByqGSM49AgEGBSuBBAAj
A4GGAAQBfav2iunAwzozmwg5lq30ltm/X3XeBgxhbsWu4Rv+I5B22urvR0jxGQM7
TsquuQ/wpmJQgTgV9jnK/5fvl4GvhS8A+K2UXv6L3IlrHIcMG3VoQ+BeKo44Hwgu
keu5GMUKAiEF33acNWUHp7U+Swxdxw+CwR9bNnIf0ZTfxlqSBaJGVIujgb4wgbsw
DgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFPhG423HoTvTKNXTAi9TKsaQwpzPMFsG
A1UdEQRUMFKGUHNwaWZmZTovL2V4YW1wbGUub3JnL3NwaXJlL2FnZW50L2pvaW5f
dG9rZW4vMmNmMzUzOGMtNGY5Yy00NmMwLWE1MjYtMWNhNjc5YTkyNDkyMAoGCCqG
SM49BAMEA4GLADCBhwJBLM2CaOSw8kzSBJUyAvg32PM1PhzsVEsGIzWS7b+hgKkJ
NlnJx6MZ82eamOCsCdTVrXUV5cxO8kt2yTmYxF+ucu0CQgGVmL65pzg2E4YfCES/
4th19FFMRiOTtNpI5j2/qLTptnanJ/rpqE0qsgA2AiSsnbnnW6B7Oa+oi7QDMOLw
l6+bdA==
-----END CERTIFICATE-----
`
	x509KeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`
	x509BundlePem = `-----BEGIN CERTIFICATE-----
MIICOTCCAZqgAwIBAgIBATAKBggqhkjOPQQDBDAeMQswCQYDVQQGEwJVUzEPMA0G
A1UECgwGU1BJRkZFMB4XDTE4MDIxMDAwMzQ0NVoXDTE4MDIxMDAxMzQ1NVowHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTCBmzAQBgcqhkjOPQIBBgUrgQQA
IwOBhgAEAZ6nXrNctKHNjZT7ZkP7xwfpMfvc/DAHc39GdT3qi8mmowY0/XuFQmlJ
cXXwv8ZlOSoGvtuLAEx1lvHNZwv4BuuPALILcIW5tyC8pjcbfqs8PMQYwiC+oFKH
BTxXzolpLeHuFLAD9ccfwWhkT1z/t4pvLkP4FCkkBosG9PVg5JQVJuZJo4GFMIGC
MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT4RuNt
x6E70yjV0wIvUyrGkMKczzAfBgNVHSMEGDAWgBRGyozl9Mjue0Y3w4c2Q+3u+wVk
CjAfBgNVHREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDBAOB
jAAwgYgCQgHOtx4sNCioAQnpEx3J/A9M6Lutth/ND/h8D+7luqEkd4tMrBQgnMj4
E0xLGUNtoFNRIrEUlgwksWvKZ3BksIIOMwJCAc8VPA/QYrlJDeQ58FKyQyrOIlPk
Q0qBJEOkL6FrAngY5218TCNUS30YS5HjI2lfyyjB+cSVFXX8Szu019dDBMhV
-----END CERTIFICATE-----
`
	x509FederatedBundlePem = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name string

		customConfig   string
		location       string
		resourceGroup  string
		subscriptionID string
		tenantID       string

		expectConfig     *Config
		expectCode       codes.Code
		expectMsgPrefix  string
		expectMgmErr     error
		expectServiceErr error
	}{
		{
			name:           "Config loaded successfully",
			location:       "location",
			resourceGroup:  "group",
			subscriptionID: "subsID",
			tenantID:       "tenantID",
			expectConfig: &Config{
				Location:       "location",
				ResourceGroup:  "group",
				SubscriptionID: "subsID",
				TenantID:       "tenantID",
			},
		},
		{
			name:            "No subscriptionID",
			tenantID:        "tenantID",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "subscription ID is required",
		},
		{
			name:            "Failed to create management client",
			subscriptionID:  "subsID",
			expectMgmErr:    errors.New("oh no"),
			expectCode:      codes.Internal,
			expectMsgPrefix: "failed to create management vault client: oh no",
		},
		{
			name:             "Failed to create service vault client",
			subscriptionID:   "subsID",
			expectServiceErr: errors.New("oh no"),
			expectCode:       codes.Internal,
			expectMsgPrefix:  "failed to create service vault client: oh no",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			}

			if tt.customConfig != "" {
				options = append(options, plugintest.Configure(tt.customConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(Config{
					Location:       tt.location,
					ResourceGroup:  tt.resourceGroup,
					SubscriptionID: tt.subscriptionID,
					TenantID:       tt.tenantID,
				}))
			}

			p := new(KeyVaultPlugin)
			p.hooks.createMgmtVaultClient = func(s string) (mgmtVaultClient, error) {
				if tt.expectMgmErr != nil {
					return nil, tt.expectMgmErr
				}
				assert.Equal(t, tt.subscriptionID, s)

				return &fakeMgmtVaultClient{}, nil
			}

			p.hooks.createServiceVaultClient = func() (serviceClientVault, error) {
				if tt.expectServiceErr != nil {
					return nil, tt.expectServiceErr
				}
				return &fakeServiceClientVault{}, nil
			}

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)

			require.Equal(t, tt.expectConfig, p.config)

			switch tt.expectCode {
			case codes.OK:
				require.Equal(t, "example.org", p.td)
				require.NotNil(t, p.mgmtVaultClient)
				require.NotNil(t, p.serviceVaultClient)
			default:
				require.Nil(t, p.mgmtVaultClient)
				require.Nil(t, p.serviceVaultClient)
			}
		})
	}
}

func TestPutX509SVID(t *testing.T) {
	x509Cert, err := pemutil.ParseCertificate([]byte(x509CertPem))
	require.NoError(t, err)

	x509Bundle, err := pemutil.ParseCertificate([]byte(x509BundlePem))
	require.NoError(t, err)

	federatedBundle, err := pemutil.ParseCertificate([]byte(x509FederatedBundlePem))
	require.NoError(t, err)

	x509Key, err := pemutil.ParseECPrivateKey([]byte(x509KeyPem))
	require.NoError(t, err)

	keyByte, err := x509.MarshalPKCS8PrivateKey(x509Key)
	require.NoError(t, err)

	successReq := &svidstorev1.PutX509SVIDRequest{
		Svid: &svidstorev1.X509SVID{
			SpiffeID:   "spiffe://example.org/lambda",
			CertChain:  [][]byte{x509Cert.Raw},
			PrivateKey: keyByte,
			Bundle:     [][]byte{x509Bundle.Raw},
			ExpiresAt:  123456,
		},
		// TODO: update secrets
		Metadata: []string{"secretname:secret1"},
		FederatedBundles: map[string][]byte{
			"federated1": federatedBundle.Raw,
		},
	}

	for _, tt := range []struct {
		name       string
		req        *svidstorev1.PutX509SVIDRequest
		expectCode codes.Code
		expectMsg  string

		mgmtClientConfig   *fakeMgmtConfig
		serviceClienConfig *fakeServiceConfig
	}{
		{
			name: "success",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			mgmtVaultClient := &fakeMgmtVaultClient{
				t: t,
				c: tt.mgmtClientConfig,
			}

			serviceClient := &fakeServiceClientVault{
				t: t,
				c: tt.serviceClienConfig,
			}

			p := new(KeyVaultPlugin)
			p.hooks.createMgmtVaultClient = mgmtVaultClient.newClient
			p.hooks.createServiceVaultClient = serviceClient.newClient

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(&Config{SubscriptionID: "subID"}),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

		})
	}
}

type fakeMgmtConfig struct {
	noTag             bool
	getErr            error
	deleteErr         error
	createOrUpdateErr error

	expectResourceGroupName string
	expectVaultName         string
	expectParameters        keyvault.VaultCreateOrUpdateParameters
}

type fakeMgmtVaultClient struct {
	t *testing.T

	c *fakeMgmtConfig
}

func (f *fakeMgmtVaultClient) newClient(s string) (mgmtVaultClient, error) {
	return f, nil
}

func (f *fakeMgmtVaultClient) Get(ctx context.Context, resourceGroupName string, vaultName string) (keyvault.Vault, error) {
	if f.c.getErr != nil {
		return keyvault.Vault{}, f.c.getErr
	}

	assert.Equal(f.t, f.c.expectResourceGroupName, resourceGroupName)
	assert.Equal(f.t, f.c.expectVaultName, vaultName)

	tags := map[string]string{}
	if f.c.noTag {
		tags["spire-svid"] = "true"
	}

	return keyvault.Vault{
		ID:   to.StringPtr(fmt.Sprintf("id_%s", vaultName)),
		Name: to.StringPtr(vaultName),
		Tags: *to.StringMapPtr(tags),
	}, nil
}

func (f *fakeMgmtVaultClient) Delete(ctx context.Context, resourceGroupName string, vaultName string) (result autorest.Response, err error) {
	if f.c.deleteErr != nil {
		return autorest.Response{}, f.c.deleteErr
	}

	assert.Equal(f.t, f.c.expectResourceGroupName, resourceGroupName)
	assert.Equal(f.t, f.c.expectVaultName, vaultName)

	return autorest.Response{}, nil
}

func (f *fakeMgmtVaultClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, parameters keyvault.VaultCreateOrUpdateParameters) (keyvault.VaultsCreateOrUpdateFuture, error) {
	if f.c.createOrUpdateErr != nil {
		return keyvault.VaultsCreateOrUpdateFuture{}, f.c.createOrUpdateErr
	}

	assert.Equal(f.t, f.c.expectResourceGroupName, resourceGroupName)
	assert.Equal(f.t, f.c.expectVaultName, vaultName)
	assert.Equal(f.t, f.c.expectParameters, parameters)

	return keyvault.VaultsCreateOrUpdateFuture{}, nil
}

type fakeServiceConfig struct {
	getSecretsErr   error
	deleteSecretErr error
	setSecretErr    error

	secretItems []kv.SecretItem

	expectVaultBaseURL string
	expectSecretName   string
	expectParameters   kv.SecretSetParameters
}

type fakeServiceClientVault struct {
	t *testing.T
	c *fakeServiceConfig
}

func (f *fakeServiceClientVault) newClient() (serviceClientVault, error) {
	return f, nil
}

func (f *fakeServiceClientVault) GetSecrets(ctx context.Context, vaultBaseURL string, maxresults *int32) (kv.SecretListResultPage, error) {
	if f.c.getSecretsErr != nil {
		return kv.SecretListResultPage{}, f.c.getSecretsErr
	}

	assert.Equal(f.t, f.c.expectVaultBaseURL, vaultBaseURL)

	nextPage := func(context.Context, kv.SecretListResult) (kv.SecretListResult, error) {
		return kv.SecretListResult{}, nil
	}
	resultPage := kv.NewSecretListResultPage(kv.SecretListResult{
		Value: &f.c.secretItems,
	}, nextPage)

	return resultPage, nil
}

func (f *fakeServiceClientVault) DeleteSecret(ctx context.Context, vaultBaseURL string, secretName string) (kv.DeletedSecretBundle, error) {
	if f.c.deleteSecretErr != nil {
		return kv.DeletedSecretBundle{}, f.c.deleteSecretErr
	}

	assert.Equal(f.t, f.c.expectVaultBaseURL, vaultBaseURL)
	assert.Equal(f.t, f.c.expectSecretName, secretName)

	return kv.DeletedSecretBundle{
		ID: to.StringPtr(fmt.Sprintf("id_%s", secretName)),
	}, nil
}

func (f *fakeServiceClientVault) SetSecret(ctx context.Context, vaultBaseURL string, secretName string, parameters kv.SecretSetParameters) (kv.SecretBundle, error) {
	if f.c.setSecretErr != nil {
		return kv.SecretBundle{}, f.c.setSecretErr
	}

	assert.Equal(f.t, f.c.expectVaultBaseURL, vaultBaseURL)
	assert.Equal(f.t, f.c.expectSecretName, secretName)
	assert.Equal(f.t, f.c.expectParameters, parameters)

	return kv.SecretBundle{
		ID: to.StringPtr(fmt.Sprintf("id_%s", secretName)),
	}, nil
}
