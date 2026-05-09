package plugindecode

import (
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"sigs.k8s.io/yaml"
)

// DecodeConfig decodes text into out using the given format.
// For HCL, uses hashicorp/hcl. For YAML, uses sigs.k8s.io/yaml.
func DecodeConfig(text string, format catalog.ConfigFormat, out any) error {
	switch format {
	case catalog.ConfigFormatYAML:
		return yaml.Unmarshal([]byte(text), out)
	default:
		return hcl.Decode(out, text)
	}
}
