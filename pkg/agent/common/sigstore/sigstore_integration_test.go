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

	ctx := t.Context()
	require.NoError(t, verifier.Init(ctx))

	selectors, err := verifier.Verify(ctx, imageID)
	require.NoError(t, err)
	require.NotEmpty(t, selectors)
	t.Logf("selectors: %v", selectors)
}

func TestVerifyRealImageGHCROldVersion(t *testing.T) {
	const imageID = "ghcr.io/spiffe/spire-agent:1.14.0"

	config := NewConfig()
	config.Logger = hclog.New(&hclog.LoggerOptions{Level: hclog.Debug})
	config.IgnoreSCT = true
	// IgnoreTlog must be false for old-format (cosign v2) images with expired Fulcio certs.
	// Cosign v3 requires the Rekor integrated timestamp to validate certificates that have
	// already expired; without it verification fails regardless of the signature format.
	config.IgnoreTlog = false
	config.IgnoreAttestations = true
	config.AllowedIdentities = map[string][]string{
		"https://token.actions.githubusercontent.com": {
			"https://github.com/spiffe/spire/.github/workflows/release_build.yaml@refs/tags/v1.14.0",
		},
	}

	verifier := NewVerifier(config)

	ctx := t.Context()
	require.NoError(t, verifier.Init(ctx))

	selectors, err := verifier.Verify(ctx, imageID)
	require.NoError(t, err)
	require.NotEmpty(t, selectors)
	t.Logf("selectors: %v", selectors)
}
