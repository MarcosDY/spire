//go:build integration

package sigstore

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestVerifyRealImageGHCR(t *testing.T) {
	const imageID = "ghcr.io/spiffe/spire-agent@sha256:643ec60add4a1d3fbb82f154aed8825fdd138d074dc4f0d7f3f5100d686059a4"

	config := NewConfig()
	config.Logger = hclog.New(&hclog.LoggerOptions{Level: hclog.Debug})
	config.IgnoreSCT = true
	config.IgnoreTlog = true
	config.IgnoreAttestations = true
	config.AllowedIdentities = map[string][]string{
		"https://token.actions.githubusercontent.com": {
			"https://github.com/spiffe/spire/.github/workflows/nightly_build.yaml@refs/heads/myacob/upgrade-cosign",
		},
	}

	verifier := NewVerifier(config)

	ctx := t.Conext()
	require.NoError(t, verifier.Init(ctx))

	selectors, err := verifier.Verify(ctx, imageID)
	require.NoError(t, err)
	require.NotEmpty(t, selectors)
	t.Logf("selectors: %v", selectors)
}
