# YAML Configuration Support

**Date:** 2026-05-09  
**Status:** Approved  
**Scope:** Experimental — safe to ship alongside existing HCL support

---

## Overview

Add YAML as an optional configuration format for SPIRE server and agent, detected by file extension (`.yaml`/`.yml`). HCL behavior is completely unchanged. This is a two-repo change: `spire-plugin-sdk` gains a format-aware proto extension; `spire` gains YAML parsing, format-aware `DataSource`, and updated built-in plugins. A `go.mod replace` directive links the local SDK during development; it is removed before upstream merge.

---

## 1. Proto Changes (spire-plugin-sdk)

**File:** `proto/spire/service/common/config/v1/config.proto`

Add a `ConfigFormat` enum and two new fields to `ConfigureRequest` and `ValidateRequest`:

```protobuf
enum ConfigFormat {
  CONFIG_FORMAT_UNSPECIFIED = 0;
  CONFIG_FORMAT_HCL = 1;
  CONFIG_FORMAT_YAML = 2;
}

message ConfigureRequest {
  CoreConfiguration core_configuration = 1;
  string hcl_configuration = 2;  // kept for backward compat with old plugins
  string configuration = 3;       // raw config string in any format
  ConfigFormat config_format = 4; // format of `configuration`
}
```

`ValidateRequest` gets the same additions. Old plugins reading only `hcl_configuration` continue to work — SPIRE populates both fields when format is HCL, and only `configuration`+`config_format` when YAML.

Regenerate with `make generate` in the SDK repo. Update SDK templates to use `decodePluginConfig` helper pattern (see Section 6).

---

## 2. go.mod Replace Directive (spire)

```
replace github.com/spiffe/spire-plugin-sdk => /Users/marcosyacob/opensource/spire-plugin-sdk
```

This is a temporary local development directive. It must be removed and replaced with a published version reference before the SPIRE PR is merged upstream.

---

## 3. ConfigFormat Type & DataSource Interface (spire)

**File:** `pkg/common/catalog/config.go`

Add a `ConfigFormat` type:

```go
type ConfigFormat int

const (
    ConfigFormatHCL  ConfigFormat = iota
    ConfigFormatYAML
)

func (f ConfigFormat) toProto() configv1.ConfigFormat {
    switch f {
    case ConfigFormatYAML:
        return configv1.ConfigFormat_CONFIG_FORMAT_YAML
    default:
        return configv1.ConfigFormat_CONFIG_FORMAT_HCL
    }
}
```

Update the `DataSource` interface:

```go
type DataSource interface {
    Load() (string, ConfigFormat, error)
    IsDynamic() bool
}
```

`FixedData` and `FileData` become structs carrying both data/path and format:

```go
type FixedData struct {
    Data   string
    Format ConfigFormat
}

func (d FixedData) Load() (string, ConfigFormat, error) {
    return d.Data, d.Format, nil
}

func (d FixedData) IsDynamic() bool { return false }

type FileData struct {
    Path   string
    Format ConfigFormat
}

func (d FileData) Load() (string, ConfigFormat, error) {
    data, err := os.ReadFile(d.Path)
    if err != nil {
        return "", d.Format, err
    }
    return string(data), d.Format, nil
}

func (d FileData) IsDynamic() bool { return true }
```

The format carried by `FileData` is the format of the plugin data file itself, defaulting to HCL (same as today). A future extension can allow `.yaml` plugin data files to auto-detect format.

---

## 4. Config File Parsing (spire)

**Files:** `cmd/spire-server/cli/run/run.go`, `cmd/spire-agent/cli/run/run.go`

Add format detection before decode:

```go
func detectFormat(path string) catalog.ConfigFormat {
    switch strings.ToLower(filepath.Ext(path)) {
    case ".yaml", ".yml":
        return catalog.ConfigFormatYAML
    default:
        return catalog.ConfigFormatHCL
    }
}
```

`ParseFile()` dispatches on format:

```go
func ParseFile(path string, expandEnv bool) (*Config, error) {
    // ... read file, expand env (unchanged) ...

    format := detectFormat(path)
    switch format {
    case catalog.ConfigFormatYAML:
        if err := parseYAML(&c, data); err != nil {
            return nil, fmt.Errorf("unable to decode YAML configuration at %q: %w", path, err)
        }
    default:
        if err := hcl.Decode(&c, data); err != nil {
            return nil, fmt.Errorf("unable to decode configuration at %q: %w", path, err)
        }
    }
    return c, nil
}
```

A warning is logged when YAML is detected:

```go
log.Warn("YAML configuration support is experimental and may change in future versions")
```

### Config struct changes

The top-level `Config` struct gains `yaml:` tags and a `PluginsRaw` field for YAML-mode plugin parsing:

```go
type Config struct {
    Server             *serverConfig          `hcl:"server"        yaml:"server"`
    Plugins            ast.Node               `hcl:"plugins"`                        // HCL only
    PluginsRaw         json.RawMessage        `yaml:"plugins"`                       // YAML only
    Telemetry          telemetry.FileConfig   `hcl:"telemetry"     yaml:"telemetry"`
    HealthChecks       health.Config          `hcl:"health_checks" yaml:"healthChecks"`
    UnusedKeyPositions map[string][]token.Pos `hcl:",unusedKeyPositions"`
}
```

All nested config structs (`serverConfig`, `agentConfig`, `experimentalConfig`, `federationConfig`, etc.) gain camelCase `yaml:` tags alongside their existing `hcl:` tags. For example:

```go
type serverConfig struct {
    BindAddress string `hcl:"bind_address" yaml:"bindAddress"`
    BindPort    int    `hcl:"bind_port"    yaml:"bindPort"`
    TrustDomain string `hcl:"trust_domain" yaml:"trustDomain"`
    // ...
}
```

`UnusedKeyPositions` fields are HCL-specific and not tagged for YAML. Unknown key detection for YAML uses `sigs.k8s.io/yaml` strict decoding instead.

The call site that dispatches plugin parsing:

```go
// in NewServerConfig / NewAgentConfig
var pluginConfigs catalog.PluginConfigs
var err error
if c.PluginsRaw != nil {
    pluginConfigs, err = catalog.PluginConfigsFromYAML(c.PluginsRaw)
} else {
    pluginConfigs, err = catalog.PluginConfigsFromHCLNode(c.Plugins)
}
```

---

## 5. Plugin Config Parsing for YAML (spire)

**File:** `pkg/common/catalog/config.go`

New function `PluginConfigsFromYAML` mirrors `PluginConfigsFromHCLNode`. The YAML plugin section structure uses camelCase:

```yaml
plugins:
  NodeAttestor:
    k8s_psat:
      pluginCmd: "./attestor"
      pluginChecksum: "abc123"
      pluginData:
        cluster: "prod"
      enabled: true
  NodeAttestor:
    plugin_disabled:
      pluginCmd: "./attestor"
      enabled: false
  KeyManager:
    disk:
      pluginDataFile: "keymanager.yaml"
```

Internal YAML plugin config struct:

```go
type yamlPluginConfig struct {
    PluginCmd      string          `yaml:"pluginCmd"`
    PluginArgs     []string        `yaml:"pluginArgs"`
    PluginChecksum string          `yaml:"pluginChecksum"`
    PluginData     map[string]any  `yaml:"pluginData"`
    PluginDataFile *string         `yaml:"pluginDataFile"`
    Enabled        *bool           `yaml:"enabled"`
}
```

`PluginData` is re-marshalled to YAML string and stored as `FixedData{Format: ConfigFormatYAML}`. `PluginDataFile` produces `FileData{Format: ConfigFormatYAML}`.

---

## 6. configure.go & gRPC Wire (spire)

**File:** `pkg/common/catalog/configure.go`

`ConfigurePlugin()` uses the updated `Load()` signature:

```go
data, format, err := dataSource.Load()
```

`configurerV1.Configure()` populates the gRPC request:

```go
req := &configv1.ConfigureRequest{
    CoreConfiguration: coreConfig.v1(),
    Configuration:     data,
    ConfigFormat:      format.toProto(),
}
// backward compat: populate hcl_configuration for old plugins
if format == catalog.ConfigFormatHCL {
    req.HclConfiguration = data
}
```

The `Configurer` interface signature is unchanged — it still receives a plain `string`. The format is consumed inside `ConfigurePlugin()` before calling `configurer.Configure()`, which now builds the full gRPC request internally using both data and format:

```go
type Configurer interface {
    Configure(ctx context.Context, coreConfig CoreConfig, configuration string) error
    Validate(ctx context.Context, coreConfig CoreConfig, configuration string) (*configv1.ValidateResponse, error)
}
```

`ConfigurePlugin()` is updated to receive format alongside data and pass it to the internal gRPC request builder without surfacing it in the public interface.

---

## 7. Built-in Plugin Updates (spire)

A shared decode helper is added (e.g. in `pkg/common/catalog/pluginconfig.go` or a new `pkg/common/plugindecode/decode.go`):

```go
func DecodePluginConfig(req *configv1.ConfigureRequest, config any) error {
    switch req.ConfigFormat {
    case configv1.ConfigFormat_CONFIG_FORMAT_YAML:
        return yaml.Unmarshal([]byte(req.Configuration), config)
    default:
        return hcl.Decode(config, cmp.Or(req.Configuration, req.HclConfiguration))
    }
}
```

`cmp.Or(req.Configuration, req.HclConfiguration)` handles both old SPIRE (only `hcl_configuration` populated) and new SPIRE (populates `configuration`).

Each built-in plugin's `Configure` method replaces:

```go
if err := hcl.Decode(config, req.HclConfiguration); err != nil { ... }
```

with:

```go
if err := plugindecode.DecodePluginConfig(req, config); err != nil { ... }
```

Each plugin's `Config` struct gets camelCase `yaml:` tags alongside existing `hcl:` tags.

---

## 8. Testing

### Unit tests
- `detectFormat()`: `.yaml` → YAML, `.yml` → YAML, `.conf` → HCL, `.hcl` → HCL, no extension → HCL
- `PluginConfigsFromYAML()`: mirrors existing `PluginConfigsFromHCLNode` test cases
- `ParseFile()` YAML: full round-trip for server and agent configs
- `DecodePluginConfig()`: both HCL and YAML dispatch paths, old-SPIRE backward compat path

### Fixtures
New files mirroring existing HCL fixtures (full field coverage, camelCase):
- `test/fixture/config/server_good_posix.yaml`
- `test/fixture/config/agent_good_posix.yaml`

### Invariant
No existing HCL tests are modified. No existing `.conf` fixtures are touched. `ParseFile` with HCL input follows the exact same code path as before.

---

## 9. Full YAML Configuration Examples

### server_good_posix.yaml

```yaml
server:
  bindAddress: "127.0.0.1"
  bindPort: 8081
  socketPath: "/tmp/spire-server/private/api-test.sock"
  trustDomain: "example.org"
  logLevel: "INFO"
  auditLogEnabled: true
  proxyProtocolTrustedCidrs:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  federation:
    bundleEndpoint:
      address: "0.0.0.0"
      port: 8443
      acme:
        domainName: "example.org"
    federatesWith:
      "domain1.test":
        bundleEndpoint:
          address: "1.2.3.4"
          useWebPki: true
      "domain2.test":
        bundleEndpoint:
          address: "5.6.7.8"
          spiffeId: "spiffe://domain2.test/bundle-provider"
      "domain3.test":
        bundleEndpointUrl: "https://9.10.11.12:8443"
        bundleEndpointProfile:
          httpsSpiffe:
            endpointSpiffeId: "spiffe://different-domain.test/my-spiffe-bundle-endpoint-server"
      "domain4.test":
        bundleEndpointUrl: "https://13.14.15.16:8444"
        bundleEndpointProfile:
          httpsWeb: {}
  experimental:
    requirePqKem: true

plugins:
  plugin_type_server:
    plugin_name_server:
      pluginCmd: "./pluginServerCmd"
      pluginChecksum: "pluginServerChecksum"
      pluginData:
        joinToken: "PLUGIN-SERVER-NOT-A-SECRET"
    plugin_disabled:
      pluginCmd: "./pluginServerCmd"
      enabled: false
      pluginChecksum: "pluginServerChecksum"
      pluginData:
        joinToken: "PLUGIN-SERVER-NOT-A-SECRET"
    plugin_enabled:
      pluginCmd: "./pluginServerCmd"
      enabled: true
      pluginChecksum: "pluginServerChecksum"
      pluginDataFile: "plugin.conf"
```

### agent_good_posix.yaml

```yaml
agent:
  bindAddress: "127.0.0.1"
  bindPort: 8088
  dataDir: "."
  logLevel: "INFO"
  serverAddress: "127.0.0.1"
  serverPort: 8081
  socketPath: "/tmp/spire-agent/public/api.sock"
  trustBundlePath: "conf/agent/dummy_root_ca.crt"
  trustDomain: "example.org"
  allowUnauthenticatedVerifiers: true
  allowedForeignJwtClaims:
    - "c1"
    - "c2"
    - "c3"

plugins:
  plugin_type_agent:
    plugin_name_agent:
      pluginCmd: "./pluginAgentCmd"
      pluginChecksum: "pluginAgentChecksum"
      pluginData:
        joinToken: "PLUGIN-AGENT-NOT-A-SECRET"
    plugin_disabled:
      pluginCmd: "./pluginAgentCmd"
      enabled: false
      pluginChecksum: "pluginAgentChecksum"
      pluginData:
        joinToken: "PLUGIN-AGENT-NOT-A-SECRET"
    plugin_enabled:
      pluginCmd: "./pluginAgentCmd"
      enabled: true
      pluginChecksum: "pluginAgentChecksum"
      pluginDataFile: "plugin.conf"
```

---

## 10. What Does NOT Change

- All existing HCL parsing code paths are untouched
- `PluginConfigsFromHCLNode` is untouched
- All existing `.conf` test fixtures are untouched
- All existing HCL-based tests pass without modification
- External plugins using `hcl_configuration` over gRPC continue to work

---

## Open Items / Follow-ups

- Remove `go.mod replace` once SDK PR is merged upstream and a new SDK version is published
- Consider allowing `pluginDataFile` to auto-detect format by extension (deferred)
- SDK plugin templates should be updated to use `DecodePluginConfig` helper (included in this change for built-ins; external plugin authors can adopt at their own pace)
