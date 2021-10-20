package azurekeyvault

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

type mgmtVaultClient interface {
	Get(ctx context.Context, resourceGroupName string, vaultName string) (result keyvault.Vault, err error)
	Delete(ctx context.Context, resourceGroupName string, vaultName string) (result autorest.Response, err error)
	CreateOrUpdate(ctx context.Context, resourceGroupName string, vaultName string, parameters keyvault.VaultCreateOrUpdateParameters) (result keyvault.VaultsCreateOrUpdateFuture, err error)
}

type serviceClientVault interface {
	GetSecrets(ctx context.Context, vaultBaseURL string, maxresults *int32) (result kv.SecretListResultPage, err error)
	DeleteSecret(ctx context.Context, vaultBaseURL string, secretName string) (result kv.DeletedSecretBundle, err error)
	SetSecret(ctx context.Context, vaultBaseURL string, secretName string, parameters kv.SecretSetParameters) (result kv.SecretBundle, err error)
}

func createMgmtVaultClient(subscriptionID string) (mgmtVaultClient, error) {
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

func createServiceVaultClient() (serviceClientVault, error) {
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
