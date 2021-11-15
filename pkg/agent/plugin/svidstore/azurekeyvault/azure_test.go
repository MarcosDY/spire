package azurekeyvault

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/gofrs/uuid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

		expectConfig    *Config
		expectCode      codes.Code
		expectMsgPrefix string
		expectClientErr error
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
			name:            "Failed to create azure client",
			subscriptionID:  "subsID",
			expectClientErr: status.Error(codes.Internal, "oh no"),
			expectCode:      codes.Internal,
			expectMsgPrefix: "oh no",
		},
		{
			name:            "Malformed config",
			customConfig:    "malformed config",
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration:",
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
			p.hooks.createAzureClient = func(s string) (client, error) {
				if tt.expectClientErr != nil {
					return nil, tt.expectClientErr
				}
				assert.Equal(t, tt.subscriptionID, s)

				return &fakeAzureClient{}, nil
			}

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)

			require.Equal(t, tt.expectConfig, p.config)

			switch tt.expectCode {
			case codes.OK:
				require.Equal(t, "example.org", p.td)
				require.NotNil(t, p.client)
			default:
				require.Nil(t, p.client)
			}
		})
	}
}

func TestPutX509SVID(t *testing.T) {
	tenantIDUUID, err := uuid.NewV4()
	require.NoError(t, err)

	defaultUUID, err := uuid.NewV4()
	require.NoError(t, err)

	x509Cert, err := pemutil.ParseCertificate([]byte(x509CertPem))
	require.NoError(t, err)

	certNotAfter := date.NewUnixTimeFromNanoseconds(x509Cert.NotAfter.UnixNano())
	certNotBefore := date.NewUnixTimeFromNanoseconds(x509Cert.NotBefore.UnixNano())

	x509Bundle, err := pemutil.ParseCertificate([]byte(x509BundlePem))
	require.NoError(t, err)

	federatedBundle, err := pemutil.ParseCertificate([]byte(x509FederatedBundlePem))
	require.NoError(t, err)

	x509Key, err := pemutil.ParseECPrivateKey([]byte(x509KeyPem))
	require.NoError(t, err)

	expiresAt := time.Now()
	successReq := &svidstore.X509SVID{
		SVID: &svidstore.SVID{
			SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/secret"),
			CertChain:  []*x509.Certificate{x509Cert},
			PrivateKey: x509Key,
			Bundle:     []*x509.Certificate{x509Bundle},
			ExpiresAt:  expiresAt,
		},
		Metadata: []string{
			"name:secret1",
			"vault:vault1",
			"group:group1",
			"tenantid:" + tenantIDUUID.String(),
			"location:location1",
		},
		FederatedBundles: map[string][]*x509.Certificate{
			"federated1": {federatedBundle},
		},
	}

	svidData := &svidstore.Data{
		SPIFFEID:    "spiffe://example.org/secret",
		X509SVID:    x509CertPem,
		X509SVIDKey: x509KeyPem,
		Bundle:      x509BundlePem,
		FederatedBundles: map[string]string{
			"federated1": x509FederatedBundlePem,
		},
	}
	secretBinary, err := json.Marshal(svidData)
	assert.NoError(t, err)
	secretStr := to.StringPtr(string(secretBinary))

	for _, tt := range []struct {
		name         string
		req          *svidstore.X509SVID
		pluginConfig *Config
		expectCode   codes.Code
		expectMsg    string

		clientConfig *fakeClientConfig

		expectGetVaultReq            *vaultReq
		expectDeleteVaultReq         *vaultReq
		expectCreateOrUpdateVaultReq *vaultReq

		expectGetSecretsReq   *secretReq
		expectDeleteSecretReq *secretReq
		expectSetSecretReq    *secretReq

		expectGetUserReq *userReq
	}{
		{
			name: "Create vault and secret",
			req:  successReq,
			pluginConfig: &Config{
				Location:       "configLocation",
				ResourceGroup:  "configGroup",
				SubscriptionID: "subsID",
				TenantID:       defaultUUID.String(),
			},
			expectCreateOrUpdateVaultReq: &vaultReq{
				resourceGroupName: "group1",
				vaultName:         "vault1",
				parameters: &keyvault.VaultCreateOrUpdateParameters{
					Location: to.StringPtr("location1"),
					Tags: map[string]*string{
						"spire-svid": to.StringPtr("example.org"),
					},
					Properties: &keyvault.VaultProperties{
						TenantID: &tenantIDUUID,
						Sku: &keyvault.Sku{
							Family: to.StringPtr("A"),
							Name:   keyvault.Standard,
						},
						AccessPolicies: &[]keyvault.AccessPolicyEntry{
							{
								ObjectID: to.StringPtr("user-id"),
								TenantID: &tenantIDUUID,
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
					},
				},
			},
			expectSetSecretReq: &secretReq{
				vaultBaseURL: "https://secret1.vault.azure.net/",
				secretName:   "secret1",
				parameters: &kv.SecretSetParameters{
					Value:       secretStr,
					ContentType: to.StringPtr("X509-SVID"),
					SecretAttributes: &kv.SecretAttributes{
						NotBefore: &certNotBefore,
						Expires:   &certNotAfter,
					},
				},
			},
			expectGetUserReq: &userReq{tenantID: tenantIDUUID.String()},
			clientConfig: &fakeClientConfig{
				getVaultErr: status.Error(codes.NotFound, "not found"),
			},
		},
		{
			name: "Use default configs when no selector set",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"vault:vault1",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			pluginConfig: &Config{
				Location:       "configLocation",
				ResourceGroup:  "configGroup",
				SubscriptionID: "subsID",
				TenantID:       defaultUUID.String(),
			},
			expectCreateOrUpdateVaultReq: &vaultReq{
				resourceGroupName: "configGroup",
				vaultName:         "vault1",
				parameters: &keyvault.VaultCreateOrUpdateParameters{
					Location: to.StringPtr("configLocation"),
					Tags: map[string]*string{
						"spire-svid": to.StringPtr("example.org"),
					},
					Properties: &keyvault.VaultProperties{
						TenantID: &defaultUUID,
						Sku: &keyvault.Sku{
							Family: to.StringPtr("A"),
							Name:   keyvault.Standard,
						},
						AccessPolicies: &[]keyvault.AccessPolicyEntry{
							{
								ObjectID: to.StringPtr("user-id"),
								TenantID: &defaultUUID,
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
					},
				},
			},
			expectSetSecretReq: &secretReq{
				vaultBaseURL: "https://secret1.vault.azure.net/",
				secretName:   "secret1",
				parameters: &kv.SecretSetParameters{
					Value:       secretStr,
					ContentType: to.StringPtr("X509-SVID"),
					SecretAttributes: &kv.SecretAttributes{
						NotBefore: &certNotBefore,
						Expires:   &certNotAfter,
					},
				},
			},
			expectGetUserReq: &userReq{tenantID: defaultUUID.String()},
			clientConfig: &fakeClientConfig{
				getVaultErr: status.Error(codes.NotFound, "not found"),
			},
		},
		{
			name: "Vault exists, create secret",
			req:  successReq,
			pluginConfig: &Config{
				Location:       "configLocation",
				ResourceGroup:  "configGroup",
				SubscriptionID: "subsID",
				TenantID:       "configTenantId",
			},
			expectSetSecretReq: &secretReq{
				vaultBaseURL: "https://secret1.vault.azure.net/",
				secretName:   "secret1",
				parameters: &kv.SecretSetParameters{
					Value:       secretStr,
					ContentType: to.StringPtr("X509-SVID"),
					SecretAttributes: &kv.SecretAttributes{
						NotBefore: &certNotBefore,
						Expires:   &certNotAfter,
					},
				},
			},
			expectGetVaultReq: &vaultReq{
				resourceGroupName: "group1",
				vaultName:         "vault1",
			},
			clientConfig: &fakeClientConfig{},
		},
		{
			name: "Malformed metadata",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"vault",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): failed to parse metadata: metadata does not contain a colon: \"vault\"",
		},
		{
			name: "Secret name required",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"vault:vault1",
					"group:group1",
					"tenantid:" + tenantIDUUID.String(),
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): secret name is required",
		},
		{
			name: "Vault name required",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"group:group1",
					"tenantid:" + tenantIDUUID.String(),
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): secret vault is required",
		},
		{
			name: "Group name required",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"vault:vault1",
					"tenantid:" + tenantIDUUID.String(),
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): secret group name is required",
		},
		{
			name: "tenant ID required",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"vault:vault1",
					"group:group1",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): secret tenant ID is required",
		},
		{
			name: "Vault has no tag",
			req:  successReq,
			clientConfig: &fakeClientConfig{
				noTag: true,
			},
			expectGetVaultReq: &vaultReq{
				resourceGroupName: "group1",
				vaultName:         "vault1",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): secret is not managed by this SPIRE deployment",
		},
		{
			name: "Failed to get Vault",
			req:  successReq,
			clientConfig: &fakeClientConfig{
				getVaultErr: status.Error(codes.Internal, "oh no"),
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(azure_keyvault): oh no",
		},
		{
			name:             "Failed to create Vault",
			req:              successReq,
			expectGetUserReq: &userReq{tenantID: tenantIDUUID.String()},
			clientConfig: &fakeClientConfig{
				getVaultErr:            status.Error(codes.NotFound, "not found"),
				createOrUpdateVaultErr: status.Error(codes.Internal, "oh no"),
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(azure_keyvault): oh no",
		},
		{
			name: "Location required when creating vault",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"vault:vault1",
					"group:group1",
					"tenantid:" + tenantIDUUID.String(),
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			clientConfig: &fakeClientConfig{
				getVaultErr:            status.Error(codes.NotFound, "not found"),
				createOrUpdateVaultErr: status.Error(codes.Internal, "oh no"),
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): location is required to create key vault",
		},
		{
			name: "Invalid tenant ID",
			req: &svidstore.X509SVID{
				SVID: successReq.SVID,
				Metadata: []string{
					"name:secret1",
					"vault:vault1",
					"group:group1",
					"tenantid:invalid",
					"location:location1",
				},
				FederatedBundles: successReq.FederatedBundles,
			},
			clientConfig: &fakeClientConfig{
				getVaultErr: status.Error(codes.NotFound, "not found"),
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `svidstore(azure_keyvault): malformed tenant ID: uuid: incorrect UUID length 7 in string "invalid"`,
		},
		{
			name: "Failed to get current user",
			req:  successReq,
			clientConfig: &fakeClientConfig{
				getVaultErr:       status.Error(codes.NotFound, "not found"),
				getCurrentUserErr: status.Error(codes.Internal, "oh no"),
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(azure_keyvault): oh no",
		},
		{
			name: "Failed to encode secret",
			req: &svidstore.X509SVID{
				SVID: &svidstore.SVID{
					SPIFFEID:   spiffeid.RequireFromString("spiffe://example.org/secret"),
					CertChain:  []*x509.Certificate{x509Cert},
					PrivateKey: x509Key,
					Bundle:     []*x509.Certificate{{Raw: []byte("invalid")}},
					ExpiresAt:  expiresAt,
				},
				Metadata:         successReq.Metadata,
				FederatedBundles: successReq.FederatedBundles,
			},
			pluginConfig: &Config{
				Location:       "configLocation",
				ResourceGroup:  "configGroup",
				SubscriptionID: "subsID",
				TenantID:       "configTenantId",
			},
			expectGetVaultReq: &vaultReq{
				resourceGroupName: "group1",
				vaultName:         "vault1",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "svidstore(azure_keyvault): failed to encode sercret:",
		},
		{
			name: "Failed to set secret",
			req:  successReq,
			pluginConfig: &Config{
				Location:       "configLocation",
				ResourceGroup:  "configGroup",
				SubscriptionID: "subsID",
				TenantID:       "configTenantId",
			},
			expectGetVaultReq: &vaultReq{
				resourceGroupName: "group1",
				vaultName:         "vault1",
			},
			clientConfig: &fakeClientConfig{
				setSecretErr: status.Error(codes.Internal, "oh no"),
			},
			expectCode: codes.Internal,
			expectMsg:  "svidstore(azure_keyvault): oh no",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			if tt.clientConfig == nil {
				tt.clientConfig = &fakeClientConfig{}
			}
			azureClient := &fakeAzureClient{
				c: tt.clientConfig,
			}

			p := newPlugin(azureClient.newClient)

			pluginConfig := tt.pluginConfig
			if pluginConfig == nil {
				pluginConfig = &Config{SubscriptionID: "subsID"}
			}

			var err error
			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
				plugintest.ConfigureJSON(pluginConfig),
			}
			ss := new(svidstore.V1)
			plugintest.Load(t, builtin(p), ss,
				options...,
			)

			err = ss.PutX509SVID(ctx, tt.req)
			spiretest.AssertGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsg)

			// Validate vault calls
			assert.Equal(t, tt.expectGetVaultReq, azureClient.getVaultReq)
			assert.Equal(t, tt.expectDeleteVaultReq, azureClient.deleteVaultReq)
			assert.Equal(t, tt.expectCreateOrUpdateVaultReq, azureClient.createOrUpdateVaultReq)

			// validate secret calls
			assert.Equal(t, tt.expectGetSecretsReq, azureClient.getSecretsReq)
			assert.Equal(t, tt.expectDeleteSecretReq, azureClient.deleteSecretReq)
			assert.Equal(t, tt.expectSetSecretReq, azureClient.setSecretReq)

			// validate get current user call
			assert.Equal(t, tt.expectGetUserReq, azureClient.getUserReq)
		})
	}
}

type fakeClientConfig struct {
	noTag bool

	getVaultErr            error
	deleteVaultErr         error
	createOrUpdateVaultErr error

	getSecretsErr   error
	deleteSecretErr error
	setSecretErr    error

	getCurrentUserErr error

	secretItems []kv.SecretItem
}

type vaultReq struct {
	resourceGroupName string
	vaultName         string
	parameters        *keyvault.VaultCreateOrUpdateParameters
}

type secretReq struct {
	vaultBaseURL string
	secretName   string
	maxResults   *int32
	parameters   *kv.SecretSetParameters
}

type userReq struct {
	tenantID string
}

type fakeAzureClient struct {
	c *fakeClientConfig

	getVaultReq            *vaultReq
	deleteVaultReq         *vaultReq
	createOrUpdateVaultReq *vaultReq

	getSecretsReq   *secretReq
	deleteSecretReq *secretReq
	setSecretReq    *secretReq

	getUserReq *userReq
}

func (f *fakeAzureClient) newClient(s string) (client, error) {
	return f, nil
}

func (f *fakeAzureClient) GetVault(ctx context.Context, resourceGroupName string, vaultName string) (*vault, error) {
	if f.c.getVaultErr != nil {
		return nil, f.c.getVaultErr
	}

	f.getVaultReq = &vaultReq{
		resourceGroupName: resourceGroupName,
		vaultName:         vaultName,
	}

	tags := map[string]string{}
	if !f.c.noTag {
		tags["spire-svid"] = "example.org"
	}

	return &vault{
		ID:   fmt.Sprintf("id_%s", vaultName),
		Name: vaultName,
		Tags: tags,
	}, nil
}

func (f *fakeAzureClient) DeleteVault(ctx context.Context, resourceGroupName string, vaultName string) error {
	if f.c.deleteVaultErr != nil {
		return f.c.deleteVaultErr
	}

	f.deleteVaultReq = &vaultReq{
		resourceGroupName: resourceGroupName,
		vaultName:         vaultName,
	}

	return nil
}

func (f *fakeAzureClient) CreateOrUpdateVault(ctx context.Context, resourceGroupName string, vaultName string, parameters keyvault.VaultCreateOrUpdateParameters) error {
	if f.c.createOrUpdateVaultErr != nil {
		return f.c.createOrUpdateVaultErr
	}

	f.createOrUpdateVaultReq = &vaultReq{
		resourceGroupName: resourceGroupName,
		vaultName:         vaultName,
		parameters:        &parameters,
	}

	return nil
}

func (f *fakeAzureClient) GetSecrets(ctx context.Context, vaultBaseURL string, maxResults *int32) ([]kv.SecretItem, error) {
	if f.c.getSecretsErr != nil {
		return nil, f.c.getSecretsErr
	}

	f.getSecretsReq = &secretReq{
		vaultBaseURL: vaultBaseURL,
		maxResults:   maxResults,
	}

	return f.c.secretItems, nil
}

func (f *fakeAzureClient) DeleteSecret(ctx context.Context, vaultBaseURL string, secretName string) (*azureSecret, error) {
	if f.c.deleteSecretErr != nil {
		return nil, f.c.deleteSecretErr
	}

	f.deleteSecretReq = &secretReq{
		vaultBaseURL: vaultBaseURL,
		secretName:   secretName,
	}

	return &azureSecret{
		ID: fmt.Sprintf("id_%s", secretName),
	}, nil
}

func (f *fakeAzureClient) SetSecret(ctx context.Context, vaultBaseURL string, secretName string, parameters kv.SecretSetParameters) (*azureSecret, error) {
	if f.c.setSecretErr != nil {
		return nil, f.c.setSecretErr
	}

	f.setSecretReq = &secretReq{
		vaultBaseURL: vaultBaseURL,
		secretName:   secretName,
		parameters:   &parameters,
	}

	return &azureSecret{
		ID: fmt.Sprintf("id_%s", secretName),
	}, nil
}

func (f *fakeAzureClient) getCurrentUser(ctx context.Context, tenantID string) (*string, error) {
	if f.c.getCurrentUserErr != nil {
		return nil, f.c.getCurrentUserErr
	}

	f.getUserReq = &userReq{
		tenantID: tenantID,
	}

	return to.StringPtr("user-id"), nil
}
