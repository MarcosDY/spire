# Agent plugin: SVIDStore "azure_keyvault"

The `azure_keyvault` plugin stores in [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) the resulting X509-SVIDs of the entries that agent is entitled to.

### Secret format

The format that is used to store in a secret issued identity is the following:

```
{
	"spiffeId": "spiffe://example.org",
	"x509Svid": "X509_CERT_CHAIN_PEM",
	"x509SvidKey": "PRIVATE_KET_PEM",
	"bundle": "X509_BUNDLE_PEM",
	"federatedBundles": {
		"spiffe://federated.org": "X509_FEDERATED_BUNDLE_PEM"
	}
}
```

### Required Azure permissions

This plugin required the following permissions in order to fuction:

```
TODO: Add permission list
```

### Limitations

Azure Key Vault stores secrets with a maximum size of 25k bytes each, that is a limitation we can not avoid.


### Configuration

| Configuration        | Description |  
| -------------------- | ------------------------------------------------------------- |  
| location             | default Azure location where the key vault should be created. |
| resource_group       | default resource group.                                       |
| subscription_id      | default subscription ID.                                      |
| tenant_id            | default Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. |

A sample cofiguration:

```
SVIDStore "azure_keyvault" {
    plugin_data {
         location = "eastus"
         resource_group = "my-group"
         subscription_id = "my-subscription-id" 
         tenant_id = "my-tenant-id" 
    }
}
```
 TODO: ADD envvars used to connect

### Store selectors

Selectors are used on `storable` entries to describre metadata that is needed by `azure_keyvault` in order to store secrets in Azure Key Vault. In case that a `required` selector is not provided, the plugin will return an error at execution time. 

| Selector                  | Example                           | Required | Description |
| ------------------------- | --------------------------------- | -------- | ----------- |
| `azure_keyvault:name`     | `azure_keyvault:name:my-secret`   | x        | The secret name where SVID will be stored |
| `azure_keyvault:vault`    | `azure_keyvault:vault:my-vault`   | x        | The secret vault where secret will be contained |
| `azure_keyvault:group`    | `azure_keyvault:group:my-group`   | -        | The Azure resource group where Vault lives, if not set uses configured default resource group on plugin |
| `azure_keyvault:location` | `azure_keyvault:location:westus2` | -        | The Azure location where key vault should be created, if not set uses configured default location on plugin. |
| `azure_keyvault:tenantid` | `azure_keyvault:tenantid:9f193d33-7c0c-4246-9a3a-c3883ee5a39e` | -       | The Azure Active directory teant ID used when creating Vault, if not set uses configured tenant ID on plugin  |

