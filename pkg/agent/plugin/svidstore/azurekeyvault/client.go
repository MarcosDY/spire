package azurekeyvault

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type client interface {
	GetVault(ctx context.Context, resourceGroupName string, vaultName string) (*vault, error)
	DeleteVault(ctx context.Context, resourceGroupName string, vaultName string) error
	CreateOrUpdateVault(ctx context.Context, resourceGroupName string, vaultName string, parameters keyvault.VaultCreateOrUpdateParameters) error

	GetSecrets(ctx context.Context, vaultBaseURL string, maxresults *int32) ([]kv.SecretItem, error)
	DeleteSecret(ctx context.Context, vaultBaseURL string, secretName string) (*azureSecret, error)
	SetSecret(ctx context.Context, vaultBaseURL string, secretName string, parameters kv.SecretSetParameters) (*azureSecret, error)

	getCurrentUser(ctx context.Context, tenantID string) (*string, error)
}

type azureClient struct {
	mgmtVault    *keyvault.VaultsClient
	serviceVault *kv.BaseClient
}

func (c *azureClient) GetVault(ctx context.Context, resourceGroupName string, vaultName string) (*vault, error) {
	vault, err := c.mgmtVault.Get(ctx, resourceGroupName, vaultName)

	switch vault.StatusCode {
	case http.StatusOK:
		return vaultRespToStruct(vault), nil

	case http.StatusNotFound:
		return nil, status.Error(codes.NotFound, "vault not found")

	default:
		return nil, status.Errorf(codes.Internal, "failed to get key vault %q: %v", vaultName, err)
	}
}

func (c *azureClient) DeleteVault(ctx context.Context, resourceGroupName string, vaultName string) error {
	_, err := c.mgmtVault.Delete(ctx, resourceGroupName, vaultName)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to delete vault %q: %v", vaultName, err)
	}

	return nil
}

func (c *azureClient) CreateOrUpdateVault(ctx context.Context, resourceGroupName string, vaultName string, parameters keyvault.VaultCreateOrUpdateParameters) error {
	_, err := c.mgmtVault.CreateOrUpdate(ctx, resourceGroupName, vaultName, parameters)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create or update Vault %q: %v", vaultName, err)
	}

	return nil
}

func (c *azureClient) GetSecrets(ctx context.Context, vaultBaseURL string, maxresults *int32) ([]kv.SecretItem, error) {
	resp, err := c.serviceVault.GetSecrets(ctx, vaultBaseURL, maxresults)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get secrets: %v", err)
	}

	return resp.Values(), nil
}

func (c *azureClient) DeleteSecret(ctx context.Context, vaultBaseURL string, secretName string) (*azureSecret, error) {
	resp, err := c.serviceVault.DeleteSecret(ctx, vaultBaseURL, secretName)
	switch resp.StatusCode {
	case http.StatusOK:
		return deleteSecretBundleToStruct(resp), err

	case http.StatusNotFound:
		return nil, status.Errorf(codes.NotFound, "secret not found")

	default:
		return nil, status.Errorf(codes.Internal, "failed to delete secret: %v", err)
	}
}

func (c *azureClient) SetSecret(ctx context.Context, vaultBaseURL string, secretName string, parameters kv.SecretSetParameters) (*azureSecret, error) {
	resp, err := c.serviceVault.SetSecret(ctx, vaultBaseURL, secretName, parameters)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to set secret: %v", err)
	}

	return secretBundleToStruct(resp), nil
}

func (c *azureClient) getCurrentUser(ctx context.Context, tenantID string) (*string, error) {
	client, err := createSignedInUserClient(tenantID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get Auth: %v", err)
	}

	user, err := client.Get(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get signed user: %v", err)
	}

	return user.ObjectID, nil
}

func createMgmtVaultClient(subscriptionID string) (*keyvault.VaultsClient, error) {
	// There are several mechanism to authenticate against azure API (https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization)
	// from file authorization was choosed
	// AUDIENCE `https://vault.azure.net` is required, it is possible to use `AZURE_AD_RESOURCE` to specify it.
	auth, err := auth.NewAuthorizerFromFileWithResource("https://vault.azure.net")
	if err != nil {
		return nil, err
	}

	client := keyvault.NewVaultsClient(subscriptionID)
	client.Authorizer = auth

	return &client, nil
}

func createServiceVaultClient() (*kv.BaseClient, error) {
	// TODO: there are several mechanism to authenticate against azure API (https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization)
	// client authorization was choosed for POC test simplificaton
	// AUDIENCE `https://vault.azure.net` is required, it is possible to use `AZURE_AD_RESOURCE` to specify it.
	authorizer, err := auth.NewAuthorizerFromFileWithResource("https://vault.azure.net")
	if err != nil {
		return nil, err
	}

	client := kv.New()
	client.Authorizer = authorizer

	return &client, nil
}

func createSignedInUserClient(tenantID string) (*graphrbac.SignedInUserClient, error) {
	// // Get graph endpoint
	// envSettings, err := auth.GetSettingsFromEnvironment()
	// if err != nil {
	// return nil, err
	// }
	// env := envSettings.Environment
	// graphEndpoint = env.GraphEndpoint

	// TODO: An alternative to hardcoded resource is to get resourses form env var (https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.management.resourcemanager.fluent.azureenvironment.graphendpoint?view=azure-dotnet)
	authorizer, err := auth.NewAuthorizerFromFileWithResource("https://graph.windows.net/")
	if err != nil {
		return nil, fmt.Errorf("failed to get Auth: %w", err)
	}

	client := graphrbac.NewSignedInUserClient(tenantID)
	client.Authorizer = authorizer

	return &client, nil
}

func createAzureClient(subscriptionID string) (client, error) {
	vaultClient, err := createMgmtVaultClient(subscriptionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create management Vault client: %v", err)
	}

	secretClient, err := createServiceVaultClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create service Vault cien: %v", err)
	}

	return &azureClient{
		mgmtVault:    vaultClient,
		serviceVault: secretClient,
	}, nil
}

type vault struct {
	ID         string
	Name       string
	Type       string
	Location   string
	Tags       map[string]string
	Properties *keyvault.VaultProperties
}

type azureSecret struct {
	ID          string
	ContentType string
	Attributes  *kv.SecretAttributes
	Tags        map[string]string
	Kid         string
	Managed     bool
}

func vaultRespToStruct(v keyvault.Vault) *vault {
	return &vault{
		ID:         to.String(v.ID),
		Name:       to.String(v.Name),
		Type:       to.String(v.Type),
		Location:   to.String(v.Location),
		Tags:       to.StringMap(v.Tags),
		Properties: v.Properties,
	}
}

func secretBundleToStruct(s kv.SecretBundle) *azureSecret {
	return &azureSecret{
		ID:          to.String(s.ID),
		ContentType: to.String(s.ContentType),
		Tags:        to.StringMap(s.Tags),
		Kid:         to.String(s.Kid),
		Managed:     to.Bool(s.Managed),
		Attributes:  s.Attributes,
	}
}

func deleteSecretBundleToStruct(s kv.DeletedSecretBundle) *azureSecret {
	return &azureSecret{
		ID:          to.String(s.ID),
		ContentType: to.String(s.ContentType),
		Tags:        to.StringMap(s.Tags),
		Kid:         to.String(s.Kid),
		Managed:     to.Bool(s.Managed),
		Attributes:  s.Attributes,
	}
}
