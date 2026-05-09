package catalog

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/require"
)

func TestParsePluginConfigsFromHCLNode(t *testing.T) {
	configs, err := PluginConfigsFromHCLNode(nil)
	require.NoError(t, err, "should fail when no plugins defined")
	require.Empty(t, configs)

	test := func(t *testing.T, configIn string) {
		root := struct {
			Plugins ast.Node `hcl:"plugins"`
		}{}
		err := hcl.Decode(&root, configIn)
		require.NoError(t, err)

		configs, err := PluginConfigsFromHCLNode(root.Plugins)
		require.NoError(t, err)

		pluginA := PluginConfig{
			Name:       "NAME3",
			Type:       "TYPE1",
			DataSource: FixedData{Data: `"DATA3"`, Format: ConfigFormatHCL},
			Disabled:   true,
		}
		pluginB := PluginConfig{
			Name: "NAME4",
			Type: "TYPE4",
		}
		pluginC := PluginConfig{
			Name:       "NAME1",
			Type:       "TYPE1",
			Path:       "CMD1",
			DataSource: FixedData{Data: `"DATA1"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginD := PluginConfig{
			Name:       "NAME5",
			Type:       "TYPE1",
			DataSource: FixedData{Data: `"foo" = "bar"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginE := PluginConfig{
			Name:       "NAME2",
			Type:       "TYPE2",
			Path:       "CMD2",
			Args:       []string{"foo", "bar", "baz"},
			Checksum:   "CHECKSUM2",
			DataSource: FixedData{Data: `"DATA2"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginF := PluginConfig{
			Name:       "NAME6",
			Type:       "TYPE3",
			DataSource: FixedData{Data: `"foo" = "bar"`, Format: ConfigFormatHCL},
			Disabled:   false,
		}
		pluginG := PluginConfig{
			Name:       "NAME7",
			Type:       "TYPE5",
			DataSource: FileData{Path: "FILE7", Format: ConfigFormatHCL},
		}
		pluginH := PluginConfig{
			Name:       "NAME8",
			Type:       "TYPE5",
			DataSource: nil,
		}

		// The declaration order should be preserved.
		require.Equal(t, PluginConfigs{
			pluginA,
			pluginB,
			pluginC,
			pluginD,
			pluginE,
			pluginF,
			pluginG,
			pluginH,
		}, configs)

		// A, C, and D are of type TYPE1
		matching, remaining := configs.FilterByType("TYPE1")

		require.Equal(t, PluginConfigs{
			pluginA,
			pluginC,
			pluginD,
		}, matching)

		require.Equal(t, PluginConfigs{
			pluginB,
			pluginE,
			pluginF,
			pluginG,
			pluginH,
		}, remaining)

		c, ok := configs.Find("TYPE1", "NAME1")
		require.Equal(t, pluginC, c)
		require.True(t, ok)

		_, ok = configs.Find("WHATEVER", "NAME1")
		require.False(t, ok)

		_, ok = configs.Find("TYPE1", "WHATEVER")
		require.False(t, ok)
	}

	t.Run("HCL", func(t *testing.T) {
		config := `
			plugins {
				TYPE1 "NAME3" {
					plugin_data = "DATA3"
					enabled = false
				}
				TYPE4 "NAME4" {
				}
				TYPE1 {
					NAME1 {
						plugin_cmd = "CMD1"
						plugin_data = "DATA1"
					}
					NAME5 plugin_data {
						"foo" = "bar"
					}
				}
				TYPE2 "NAME2" {
					plugin_cmd = "CMD2"
					plugin_args = ["foo", "bar", "baz"]
					plugin_checksum = "CHECKSUM2"
					plugin_data = "DATA2"
					enabled = true
				}
				TYPE3 "NAME6" "plugin_data" {
					"foo" = "bar"
				}
				TYPE5 "NAME7" {
					plugin_data_file = "FILE7"
				}
				TYPE5 "NAME8" {
					plugin_data = {}
				}
			}
		`
		test(t, config)
	})

	t.Run("JSON", func(t *testing.T) {
		config := `{
			  "plugins": {
				"TYPE1": [
				  {
					"NAME3": {
						"plugin_data": "DATA3",
						"enabled": false
					}
				  }
				],
				"TYPE4": [
				  {
					"NAME4": [
					  {
					  }
					]
				  }
				],
				"TYPE1": [
				  {
					"NAME1": [
					  {
						"plugin_cmd": "CMD1",
						"plugin_data": "DATA1"
					  }
					]
				  },
				  {
					"NAME5": [
					  {
						"plugin_data": {
							"foo": "bar",
						}
					  }
					]
				  }
				],
				"TYPE2": [
				  {
					"NAME2": [
						{
							"plugin_cmd": "CMD2",
							"plugin_args": ["foo", "bar", "baz"],
							"plugin_checksum": "CHECKSUM2",
							"plugin_data": "DATA2",
							"enabled": true
						}
					]
				  }
				],
				"TYPE3": [
					{
						"NAME6": {
							"plugin_data": {
								"foo": "bar"
							}
						}
					}
				],
				"TYPE5": [
					{
						"NAME7": {
							"plugin_data_file": "FILE7"
						}
					},
					{
						"NAME8": {
							"plugin_data": {}
						}
					}
				],
			  }
			}`
		test(t, config)
	})

	t.Run("Plugin declared more than once", func(t *testing.T) {
		config := `{
			  "plugins": {
				"TYPE": [
					{
						"NAME": {}
					},
				],
				"TYPE": [
					{
						"NAME": {}
					},
				]
			  }
			}`
		root := struct {
			Plugins ast.Node `hcl:"plugins"`
		}{}
		err := hcl.Decode(&root, config)
		require.NoError(t, err)

		_, err = PluginConfigsFromHCLNode(root.Plugins)
		require.EqualError(t, err, `plugin "TYPE"/"NAME" declared more than once`)
	})

	t.Run("Both plugin_data and plugin_data_file are declared", func(t *testing.T) {
		config := `
			plugins {
				TYPE "NAME" {
					plugin_data = "DATA"
					plugin_data_file = "DATAFILE"
				}
			}
		`
		root := struct {
			Plugins ast.Node `hcl:"plugins"`
		}{}
		err := hcl.Decode(&root, config)
		require.NoError(t, err)

		_, err = PluginConfigsFromHCLNode(root.Plugins)
		require.EqualError(t, err, `failed to create plugin config for "TYPE"/"NAME": only one of [plugin_data, plugin_data_file] can be used`)
	})
}

func TestConfigFormat_toProto(t *testing.T) {
	require.Equal(t, configv1.ConfigFormat_CONFIG_FORMAT_HCL, ConfigFormatHCL.ToProto())
	require.Equal(t, configv1.ConfigFormat_CONFIG_FORMAT_YAML, ConfigFormatYAML.ToProto())
}

func TestFixedData_Load(t *testing.T) {
	d := FixedData{Data: "hello", Format: ConfigFormatYAML}
	data, format, err := d.Load()
	require.NoError(t, err)
	require.Equal(t, "hello", data)
	require.Equal(t, ConfigFormatYAML, format)
}

func TestPluginConfigsFromYAML(t *testing.T) {
	raw := json.RawMessage(`{
		"NodeAttestor": {
			"k8s_psat": {
				"pluginCmd": "./attestor",
				"pluginChecksum": "abc123",
				"pluginArgs": ["--arg1", "--arg2"],
				"pluginData": {"cluster": "prod"},
				"enabled": true
			},
			"disabled_plugin": {
				"pluginCmd": "./attestor2",
				"enabled": false
			}
		},
		"KeyManager": {
			"disk": {
				"pluginDataFile": "keymanager.yaml"
			}
		}
	}`)

	configs, err := PluginConfigsFromYAML(raw)
	require.NoError(t, err)
	require.Len(t, configs, 3)

	attestor, ok := configs.Find("NodeAttestor", "k8s_psat")
	require.True(t, ok)
	require.Equal(t, "./attestor", attestor.Path)
	require.Equal(t, "abc123", attestor.Checksum)
	require.Equal(t, []string{"--arg1", "--arg2"}, attestor.Args)
	require.False(t, attestor.Disabled)
	require.NotNil(t, attestor.DataSource)
	data, format, err := attestor.DataSource.Load()
	require.NoError(t, err)
	require.Equal(t, ConfigFormatYAML, format)
	require.Contains(t, data, "cluster")

	disabled, ok := configs.Find("NodeAttestor", "disabled_plugin")
	require.True(t, ok)
	require.True(t, disabled.Disabled)

	km, ok := configs.Find("KeyManager", "disk")
	require.True(t, ok)
	require.NotNil(t, km.DataSource)
	_, format2, _ := km.DataSource.Load()
	require.Equal(t, ConfigFormatYAML, format2)
}

func TestPluginConfigsFromYAML_Nil(t *testing.T) {
	configs, err := PluginConfigsFromYAML(nil)
	require.NoError(t, err)
	require.Nil(t, configs)
}

func TestPluginConfigsFromYAML_BothDataSources(t *testing.T) {
	raw := json.RawMessage(`{"T":{"n":{"pluginData":{"k":"v"},"pluginDataFile":"f.yaml"}}}`)
	_, err := PluginConfigsFromYAML(raw)
	require.ErrorContains(t, err, "only one of")
}

func TestFileData_Load(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString("key: value")
	require.NoError(t, err)
	f.Close()

	d := FileData{Path: f.Name(), Format: ConfigFormatYAML}
	data, format, err := d.Load()
	require.NoError(t, err)
	require.Equal(t, "key: value", data)
	require.Equal(t, ConfigFormatYAML, format)
}
