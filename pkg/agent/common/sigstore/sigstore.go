package sigstore

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgcert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	imageSignatureVerifiedSelector    = "image-signature:verified"
	imageAttestationsVerifiedSelector = "image-attestations:verified"
	// cosignSigArtifactType is the OCI artifact type cosign uses for signatures stored via OCI referrers.
	cosignSigArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	publicRekorURL        = "https://rekor.sigstore.dev"
)

var (
	oidcIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

	// errFallbackTagNotFound is returned when the OCI referrers fallback tag does not exist.
	// Images signed with the legacy cosign v2 format use a .sig tag instead; when the fallback
	// tag is missing the standard-path error is more informative than this one.
	errFallbackTagNotFound = errors.New("referrers fallback tag not found")
)

type Verifier interface {
	// Verify verifies an image and returns a list of selectors.
	Verify(ctx context.Context, imageID string) ([]string, error)
}

// ImageVerifier implements the Verifier interface.
type ImageVerifier struct {
	config *Config

	verificationCache sync.Map
	allowedIdentities []cosign.Identity
	authOptions       map[string]remote.Option

	rekorClient         *rekorclient.Rekor
	fulcioRoots         *x509.CertPool
	fulcioIntermediates *x509.CertPool
	rekorPublicKeys     *cosign.TrustedTransparencyLogPubKeys
	ctLogPublicKeys     *cosign.TrustedTransparencyLogPubKeys
	trustedRoot         sgroot.TrustedMaterial

	// Pre-built for bundle verification: avoids recreating on every Verify() call and
	// compiles regex matchers from allowedIdentities exactly once during Init().
	sgVerifier       *sgverify.Verifier
	sgCertIdentities []sgverify.CertificateIdentity

	sigstoreFunctions sigstoreFunctions
}

type sigstoreFunctions struct {
	verifyImageSignatures   cosignVerifyImageSignaturesFn
	verifyImageAttestations cosignVerifyImageAttestationsFn
	getRekorClient          getRekorClientFn
	getFulcioRoots          getCertPoolFn
	getFulcioIntermediates  getCertPoolFn
	getRekorPublicKeys      getTLogPublicKeysFn
	getCTLogPublicKeys      getTLogPublicKeysFn
	getTrustedRoot          getTrustedRootFn
	remoteIndex             remoteIndexFn
	resolveDigest           resolveDigestFn
	cosignRemoteSignatures  cosignRemoteSignaturesFn
	cosignVerifySignature   cosignVerifySignatureFn
	cosignRemoteBundle      cosignRemoteBundleFn
}

type cosignVerifyImageSignaturesFn func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
type cosignVerifyImageAttestationsFn func(context.Context, name.Reference, *cosign.CheckOpts, ...name.Option) ([]oci.Signature, bool, error)
type getRekorClientFn func(string, ...client.Option) (*rekorclient.Rekor, error)
type getCertPoolFn func() (*x509.CertPool, error)
type getTLogPublicKeysFn func(context.Context) (*cosign.TrustedTransparencyLogPubKeys, error)
type getTrustedRootFn func() (sgroot.TrustedMaterial, error)
type remoteIndexFn func(name.Reference, ...remote.Option) (gcv1.ImageIndex, error)
type resolveDigestFn func(name.Reference, ...cosignremote.Option) (name.Digest, error)
type cosignRemoteSignaturesFn func(name.Reference, ...cosignremote.Option) (oci.Signatures, error)
type cosignVerifySignatureFn func(context.Context, oci.Signature, gcv1.Hash, *cosign.CheckOpts) (bool, error)
type cosignRemoteBundleFn func(name.Reference, ...cosignremote.Option) (*sgbundle.Bundle, error)

func NewVerifier(config *Config) *ImageVerifier {
	verifier := &ImageVerifier{
		config:      config,
		authOptions: processRegistryCredentials(config.RegistryCredentials, config.Logger),
		sigstoreFunctions: sigstoreFunctions{
			verifyImageSignatures:   cosign.VerifyImageSignatures,
			verifyImageAttestations: cosign.VerifyImageAttestations,
			getRekorClient:          client.GetRekorClient,
			getFulcioRoots:          fulcioroots.Get,
			getFulcioIntermediates:  fulcioroots.GetIntermediates,
			getRekorPublicKeys:      cosign.GetRekorPubs,
			getCTLogPublicKeys:      cosign.GetCTLogPubs,
			getTrustedRoot:          buildGetTrustedRootFn(config.TrustedRootPath),
			remoteIndex:             remote.Index,
			resolveDigest:           cosignremote.ResolveDigest,
			cosignRemoteSignatures:  cosignremote.Signatures,
			cosignVerifySignature:   cosign.VerifyImageSignature,
			cosignRemoteBundle:      cosignremote.Bundle,
		},
	}

	if verifier.config.Logger == nil {
		verifier.config.Logger = hclog.Default()
	}

	if verifier.config.RekorURL == "" {
		verifier.config.RekorURL = publicRekorURL
	}

	verifier.allowedIdentities = processAllowedIdentities(config.AllowedIdentities)

	return verifier
}

// Init prepares the verifier by retrieving the Fulcio certificates and Rekor and CT public keys.
func (v *ImageVerifier) Init(ctx context.Context) error {
	var err error
	v.fulcioRoots, err = v.sigstoreFunctions.getFulcioRoots()
	if err != nil {
		return fmt.Errorf("failed to get fulcio root certificates: %w", err)
	}

	v.fulcioIntermediates, err = v.sigstoreFunctions.getFulcioIntermediates()
	if err != nil {
		return fmt.Errorf("failed to get fulcio intermediate certificates: %w", err)
	}

	if !v.config.IgnoreTlog {
		v.rekorPublicKeys, err = v.sigstoreFunctions.getRekorPublicKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to get rekor public keys: %w", err)
		}
		v.rekorClient, err = v.sigstoreFunctions.getRekorClient(v.config.RekorURL, client.WithLogger(v.config.Logger))
		if err != nil {
			return fmt.Errorf("failed to get rekor client: %w", err)
		}
	}

	if !v.config.IgnoreSCT {
		v.ctLogPublicKeys, err = v.sigstoreFunctions.getCTLogPublicKeys(ctx)
		if err != nil {
			return fmt.Errorf("failed to get CT log public keys: %w", err)
		}
	}

	v.trustedRoot, err = v.sigstoreFunctions.getTrustedRoot()
	if err != nil {
		return fmt.Errorf("failed to fetch trusted root for bundle verification: %w", err)
	}

	// Convert allowed identities to sigstore-go CertificateIdentity once so regex patterns
	// are compiled here rather than on every Verify() call.
	for _, identity := range v.allowedIdentities {
		certID, err := cosignIdentityToSGVerify(identity)
		if err != nil {
			return fmt.Errorf("failed to convert allowed identity for bundle verification: %w", err)
		}
		v.sgCertIdentities = append(v.sgCertIdentities, certID)
	}

	// Build the bundle verifier once respecting IgnoreTlog.
	// When IgnoreTlog=false: require full tlog inclusion proof AND use the embedded integrated
	// timestamp to validate the short-lived Fulcio certificate (no network call needed; the tlog
	// entry is embedded in the bundle).
	// When IgnoreTlog=true: skip tlog entirely and verify the cert against the current system
	// time. This only works while the Fulcio cert is still valid (~10 min), which is intentional
	// — callers that skip tlog for air-gapped deployments should use long-lived certificates.
	sgOpts := []sgverify.VerifierOption{sgverify.WithIntegratedTimestamps(1)}
	if v.config.IgnoreTlog {
		sgOpts = []sgverify.VerifierOption{sgverify.WithCurrentTime()}
	} else {
		sgOpts = append(sgOpts, sgverify.WithTransparencyLog(1))
	}
	v.sgVerifier, err = sgverify.NewVerifier(v.trustedRoot, sgOpts...)
	if err != nil {
		return fmt.Errorf("failed to create bundle verifier: %w", err)
	}

	return nil
}

// Verify validates image's signatures, attestations, and transparency logs using Cosign and Rekor.
// The imageID parameter is expected to be in the format "repository@sha256:digest".
// It returns selectors based on the image signature and rekor bundle details.
// Cosign ensures the image's signature issuer and subject match the configured allowed identities.
// If the image is in the skip list, it bypasses verification and returns an empty list of selectors.
// Uses a cache to avoid redundant verifications.
// An error is returned if the verification of the images signatures or attestations fails.
func (v *ImageVerifier) Verify(ctx context.Context, imageID string) ([]string, error) {
	v.config.Logger.Debug("Verifying image with sigstore", telemetry.ImageID, imageID)

	// Check if the image is in the list of excluded images to determine if verification should be bypassed.
	if _, ok := v.config.SkippedImages[imageID]; ok {
		// Return an empty list, indicating no verification was performed.
		return []string{}, nil
	}

	// Check the cache for previously verified selectors.
	if cachedSelectors, ok := v.verificationCache.Load(imageID); ok {
		if cachedSelectors != nil {
			v.config.Logger.Debug("Sigstore verifier cache hit", telemetry.ImageID, imageID)
			return cachedSelectors.([]string), nil
		}
	}

	imageRef, err := name.ParseReference(imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	registryURL := imageRef.Context().RegistryStr()
	authOption, exists := v.authOptions[registryURL]
	if !exists {
		authOption = remote.WithAuthFromKeychain(authn.DefaultKeychain)
	}

	checkOptions := &cosign.CheckOpts{
		RekorClient:        v.rekorClient,
		RootCerts:          v.fulcioRoots,
		IntermediateCerts:  v.fulcioIntermediates,
		RekorPubKeys:       v.rekorPublicKeys,
		CTLogPubKeys:       v.ctLogPublicKeys,
		Identities:         v.allowedIdentities,
		IgnoreSCT:          v.config.IgnoreSCT,
		IgnoreTlog:         v.config.IgnoreTlog,
		RegistryClientOpts: []cosignremote.Option{cosignremote.WithRemoteOptions(authOption)},
		// needed for cosign v3 signatures (OCI referrers)
		ExperimentalOCI11: true,
	}

	// Try the standard cosign path first. On failure, fall back to the OCI referrers fallback
	// tag, which handles registries that return HTTP 405 for the Referrers API (e.g. ghcr.io)
	// and images signed with Sigstore Bundle v0.3 (cosign v3 default).
	var (
		signatures      []oci.Signature
		fallbackDetails []*signatureDetails
		usedFallback    bool
	)
	signatures, sigErr := v.verifySignatures(ctx, imageRef, checkOptions)
	if sigErr != nil {
		v.config.Logger.Debug("Standard verification failed, trying OCI referrers fallback tag",
			telemetry.ImageID, imageRef.Name(), "error", sigErr)
		var err error
		fallbackDetails, err = v.verifyViaOCIFallbackTag(ctx, imageRef, checkOptions)
		if err != nil {
			if errors.Is(err, errFallbackTagNotFound) {
				// No OCI referrers fallback tag means the image uses the legacy .sig-tag format;
				// the standard-path error is the real failure reason.
				return nil, sigErr
			}
			return nil, err
		}
		usedFallback = true
	}

	selectors := []string{imageSignatureVerifiedSelector}

	if !v.config.IgnoreAttestations {
		attestations, err := v.verifyAttestations(ctx, imageRef, checkOptions)
		if err != nil {
			return nil, err
		}
		if len(attestations) > 0 {
			selectors = append(selectors, imageAttestationsVerifiedSelector)
		}
	}

	var detailsList []*signatureDetails
	if usedFallback {
		detailsList = fallbackDetails
	} else {
		var err error
		detailsList, err = v.extractDetailsFromSignatures(signatures)
		if err != nil {
			return nil, fmt.Errorf("failed to extract details from signatures for image %q: %w", imageID, err)
		}
	}

	selectors = append(selectors, formatDetailsAsSelectors(detailsList)...)
	v.verificationCache.Store(imageID, selectors)
	return selectors, nil
}

func (v *ImageVerifier) verifySignatures(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, error) {
	v.config.Logger.Debug("Verifying image signatures", telemetry.ImageID, imageRef.Name())

	signatures, bundleVerified, err := v.sigstoreFunctions.verifyImageSignatures(ctx, imageRef, checkOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signatures: %w", err)
	}
	if !bundleVerified && !v.config.IgnoreTlog {
		return nil, fmt.Errorf("rekor bundle not verified for image: %s", imageRef.Name())
	}
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no verified signature returned by cosign for image: %s", imageRef.Name())
	}

	return signatures, nil
}

// verifyViaOCIFallbackTag verifies signatures by reading the OCI referrers fallback tag directly,
// bypassing the Referrers API entirely. This is needed when a registry returns HTTP 405 for the
// Referrers API (e.g. ghcr.io), which prevents go-containerregistry from reaching its own
// fallback-tag logic (it only falls back on 404/400/406). Handles both legacy cosign signature
// format and Sigstore Bundle v0.3 (cosign v3 default).
//
// authOpt is resolved here from v.authOptions rather than being passed from Verify() to avoid
// threading the same value through two separate parameters (it is already embedded in
// checkOptions.RegistryClientOpts as a cosignremote.Option, but remote.Index needs the raw
// remote.Option type which cannot be extracted back out of a cosignremote.Option).
func (v *ImageVerifier) verifyViaOCIFallbackTag(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]*signatureDetails, error) {
	registryURL := imageRef.Context().RegistryStr()
	authOpt, exists := v.authOptions[registryURL]
	if !exists {
		authOpt = remote.WithAuthFromKeychain(authn.DefaultKeychain)
	}

	digest, err := v.sigstoreFunctions.resolveDigest(imageRef, checkOptions.RegistryClientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image digest: %w", err)
	}

	h, err := gcv1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("failed to parse image digest: %w", err)
	}

	// OCI Distribution Spec referrers fallback tag: "sha256:<hash>" -> "sha256-<hash>"
	fallbackTagStr := strings.Replace(digest.Identifier(), ":", "-", 1)
	fallbackRef, err := name.ParseReference(fmt.Sprintf("%s:%s", digest.Repository.String(), fallbackTagStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse fallback tag reference: %w", err)
	}

	idx, err := v.sigstoreFunctions.remoteIndex(fallbackRef, authOpt)
	if err != nil {
		// If the fallback tag itself does not exist the registry returns 404 MANIFEST_UNKNOWN.
		// This means the image was signed with the legacy .sig-tag format, not OCI referrers.
		// Signal the caller so it can surface the original standard-path error instead.
		var te *transport.Error
		if errors.As(err, &te) && te.StatusCode == http.StatusNotFound {
			return nil, errFallbackTagNotFound
		}
		return nil, fmt.Errorf("failed to fetch OCI referrers fallback tag: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}

	var allDetails []*signatureDetails
	bundleVerified := false

	for _, m := range manifest.Manifests {
		sigRef, err := name.ParseReference(fmt.Sprintf("%s@%s", digest.Repository.String(), m.Digest.String()))
		if err != nil {
			v.config.Logger.Debug("Failed to parse referrer manifest reference", "error", err)
			continue
		}

		if m.ArtifactType == cosignSigArtifactType {
			// Legacy cosign v2 signature format
			sigs, err := v.sigstoreFunctions.cosignRemoteSignatures(sigRef, checkOptions.RegistryClientOpts...)
			if err != nil {
				v.config.Logger.Debug("Failed to fetch signatures from manifest", "error", err)
				continue
			}
			sigList, err := sigs.Get()
			if err != nil {
				v.config.Logger.Debug("Failed to list signatures", "error", err)
				continue
			}
			for _, sig := range sigList {
				ok, err := v.sigstoreFunctions.cosignVerifySignature(ctx, sig, h, checkOptions)
				if err != nil {
					v.config.Logger.Debug("Legacy signature verification failed", "error", err)
					continue
				}
				// Only collect details for signatures whose tlog bundle was verified.
				// Collecting details for unverified signatures would produce selectors for
				// signatures that failed tlog verification, masking the bundleVerified check below.
				if !ok && !v.config.IgnoreTlog {
					v.config.Logger.Debug("Legacy signature tlog bundle not verified, skipping")
					continue
				}
				details, err := extractSignatureDetails(sig, v.config.IgnoreTlog)
				if err != nil {
					v.config.Logger.Debug("Failed to extract legacy signature details", "error", err)
					continue
				}
				allDetails = append(allDetails, details)
				if ok {
					bundleVerified = true
				}
			}
		} else {
			// Sigstore Bundle v0.3 format (cosign v3 default)
			bundle, err := v.sigstoreFunctions.cosignRemoteBundle(sigRef, checkOptions.RegistryClientOpts...)
			if err != nil {
				v.config.Logger.Debug("Not a sigstore bundle manifest", "artifactType", m.ArtifactType, "error", err)
				continue
			}
			details, err := v.verifyBundle(ctx, bundle, h, checkOptions)
			if err != nil {
				v.config.Logger.Debug("Bundle verification failed", "error", err)
				continue
			}
			allDetails = append(allDetails, details)
			bundleVerified = true
		}
	}

	if len(allDetails) == 0 {
		return nil, errors.New("failed to verify signatures: no signatures found")
	}
	if !bundleVerified && !v.config.IgnoreTlog {
		return nil, fmt.Errorf("rekor bundle not verified for image: %s", imageRef.Name())
	}

	return allDetails, nil
}

// verifyBundle verifies a Sigstore Bundle v0.3 using the pre-built verifier and identities.
func (v *ImageVerifier) verifyBundle(ctx context.Context, bundle *sgbundle.Bundle, h gcv1.Hash, checkOptions *cosign.CheckOpts) (*signatureDetails, error) {
	_ = ctx // reserved for future use (e.g. network calls in sgVerifier)
	policyOpts := make([]sgverify.PolicyOption, len(v.sgCertIdentities))
	for i, certID := range v.sgCertIdentities {
		policyOpts[i] = sgverify.WithCertificateIdentity(certID)
	}

	digestBytes, err := hex.DecodeString(h.Hex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image digest: %w", err)
	}

	pb := sgverify.NewPolicy(sgverify.WithArtifactDigest(h.Algorithm, digestBytes), policyOpts...)
	result, err := v.sgVerifier.Verify(bundle, pb)
	if err != nil {
		return nil, fmt.Errorf("bundle verification failed: %w", err)
	}

	return extractDetailsFromBundle(result, bundle, checkOptions.IgnoreTlog)
}

func (v *ImageVerifier) verifyAttestations(ctx context.Context, imageRef name.Reference, checkOptions *cosign.CheckOpts) ([]oci.Signature, error) {
	v.config.Logger.Debug("Verifying image attestations", telemetry.ImageID, imageRef.Name())

	// Verify the image's attestations using cosign.VerifyImageAttestations
	attestations, bundleVerified, err := v.sigstoreFunctions.verifyImageAttestations(ctx, imageRef, checkOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to verify image attestations: %w", err)
	}
	if len(attestations) > 0 && !bundleVerified && !v.config.IgnoreTlog {
		return nil, fmt.Errorf("rekor bundle not verified for image: %s", imageRef.Name())
	}

	return attestations, nil
}

func (v *ImageVerifier) extractDetailsFromSignatures(signatures []oci.Signature) ([]*signatureDetails, error) {
	var detailsList []*signatureDetails
	for _, signature := range signatures {
		details, err := extractSignatureDetails(signature, v.config.IgnoreTlog)
		if err != nil {
			return nil, err
		}
		detailsList = append(detailsList, details)
	}
	return detailsList, nil
}

func extractSignatureDetails(signature oci.Signature, ignoreTlog bool) (*signatureDetails, error) {
	cert, err := getCertificate(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from signature: %w", err)
	}

	subject, err := extractSubject(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract subject from certificate: %w", err)
	}

	issuer, err := extractIssuer(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer from certificate: %w", err)
	}

	base64Signature, err := signature.Base64Signature()
	if err != nil {
		return nil, fmt.Errorf("failed to extract base64 signature from certificate: %w", err)
	}

	var logIndex string
	var logID string
	var signedEntryTimestamp string
	var integratedTime string
	if !ignoreTlog {
		rekorBundle, err := signature.Bundle()
		if err != nil {
			return nil, fmt.Errorf("failed to get signature rekor bundle: %w", err)
		}

		logID = rekorBundle.Payload.LogID
		logIndex = strconv.FormatInt(rekorBundle.Payload.LogIndex, 10)
		integratedTime = strconv.FormatInt(rekorBundle.Payload.IntegratedTime, 10)
		signedEntryTimestamp = base64.StdEncoding.EncodeToString(rekorBundle.SignedEntryTimestamp)
	}

	return &signatureDetails{
		Subject:              subject,
		Issuer:               issuer,
		Signature:            base64Signature,
		LogID:                logID,
		LogIndex:             logIndex,
		IntegratedTime:       integratedTime,
		SignedEntryTimestamp: signedEntryTimestamp,
	}, nil
}

func getCertificate(signature oci.Signature) (*x509.Certificate, error) {
	if signature == nil {
		return nil, errors.New("signature is nil")
	}
	cert, err := signature.Cert()
	if err != nil {
		return nil, fmt.Errorf("failed to access signature certificate: %w", err)
	}
	if cert == nil {
		return nil, errors.New("no certificate found in signature")
	}
	return cert, nil
}

func extractSubject(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}

	subjectAltNames := cryptoutils.GetSubjectAlternateNames(cert)
	if len(subjectAltNames) == 0 {
		return "", errors.New("no subject found in certificate")
	}

	for _, san := range subjectAltNames {
		if san != "" {
			return san, nil
		}
	}

	return "", errors.New("subject alternative names are present but all are empty")
}

func extractIssuer(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidcIssuerOID) {
			issuer := string(ext.Value)
			if issuer == "" {
				return "", errors.New("OIDC issuer extension is present but empty")
			}
			return issuer, nil
		}
	}

	return "", errors.New("no OIDC issuer found in certificate extensions")
}

type signatureDetails struct {
	Subject              string
	Issuer               string
	Signature            string
	LogID                string
	LogIndex             string
	IntegratedTime       string
	SignedEntryTimestamp string
}

func formatDetailsAsSelectors(detailsList []*signatureDetails) []string {
	var selectors []string
	for _, details := range detailsList {
		selectors = append(selectors, detailsToSelectors(details)...)
	}
	return selectors
}

func detailsToSelectors(details *signatureDetails) []string {
	var selectors []string
	if details.Subject != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-subject:%s", details.Subject))
	}
	if details.Issuer != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-issuer:%s", details.Issuer))
	}
	if details.Signature != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-value:%s", details.Signature))
	}
	if details.LogID != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-log-id:%s", details.LogID))
	}
	if details.LogIndex != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-log-index:%s", details.LogIndex))
	}
	if details.IntegratedTime != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-integrated-time:%s", details.IntegratedTime))
	}
	if details.SignedEntryTimestamp != "" {
		selectors = append(selectors, fmt.Sprintf("image-signature-signed-entry-timestamp:%s", details.SignedEntryTimestamp))
	}
	return selectors
}

func processRegistryCredentials(credentials map[string]*RegistryCredential, logger hclog.Logger) map[string]remote.Option {
	authOptions := make(map[string]remote.Option)

	for registry, creds := range credentials {
		if creds == nil {
			continue
		}

		usernameProvided := creds.Username != ""
		passwordProvided := creds.Password != ""

		if usernameProvided && passwordProvided {
			authOption := remote.WithAuth(&authn.Basic{
				Username: creds.Username,
				Password: creds.Password,
			})
			authOptions[registry] = authOption
		} else if usernameProvided || passwordProvided {
			logger.Warn("Incomplete credentials for registry %q. Both username and password must be provided.", registry)
		}
	}

	return authOptions
}

func processAllowedIdentities(allowedIdentities map[string][]string) []cosign.Identity {
	var identities []cosign.Identity
	for issuer, subjects := range allowedIdentities {
		for _, subject := range subjects {
			identity := cosign.Identity{}

			if containsRegexChars(issuer) {
				identity.IssuerRegExp = normalizeGlobPattern(issuer)
			} else {
				identity.Issuer = issuer
			}

			if containsRegexChars(subject) {
				identity.SubjectRegExp = normalizeGlobPattern(subject)
			} else {
				identity.Subject = subject
			}

			identities = append(identities, identity)
		}
	}
	return identities
}

func containsRegexChars(s string) bool {
	// check for characters commonly used in regex.
	return strings.ContainsAny(s, "*+?^${}[]|()")
}

// normalizeGlobPattern converts a pattern that may use glob-style wildcards into a valid
// Go regular expression. Specifically, a bare '*' (not already preceded by '.') is replaced
// with '.*' so that patterns like '*@example.com' or 'refs/tags/*' work as intended.
// Patterns that already use proper regex (e.g. '.*@example\.com') are left unchanged.
func normalizeGlobPattern(pattern string) string {
	if !strings.Contains(pattern, "*") {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern) + 4)
	for i := range len(pattern) {
		if pattern[i] == '*' && (i == 0 || pattern[i-1] != '.') {
			b.WriteByte('.')
		}
		b.WriteByte(pattern[i])
	}
	return b.String()
}

func extractDetailsFromBundle(result *sgverify.VerificationResult, bundle *sgbundle.Bundle, ignoreTlog bool) (*signatureDetails, error) {
	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errors.New("no certificate in bundle verification result")
	}
	cert := result.Signature.Certificate

	subject := cert.SubjectAlternativeName
	issuer := cert.Extensions.Issuer
	if subject == "" {
		return nil, errors.New("no subject alternative name in bundle certificate")
	}
	if issuer == "" {
		return nil, errors.New("no issuer in bundle certificate extensions")
	}

	details := &signatureDetails{
		Subject: subject,
		Issuer:  issuer,
	}

	if !ignoreTlog {
		entries, err := bundle.TlogEntries()
		if err != nil {
			return nil, fmt.Errorf("failed to get tlog entries from bundle: %w", err)
		}
		if len(entries) > 0 {
			entry := entries[0]
			details.LogID = entry.LogKeyID()
			details.LogIndex = strconv.FormatInt(entry.LogIndex(), 10)
			details.IntegratedTime = strconv.FormatInt(entry.IntegratedTime().Unix(), 10)
			tle := entry.TransparencyLogEntry()
			if tle != nil && tle.InclusionPromise != nil {
				details.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(
					tle.InclusionPromise.GetSignedEntryTimestamp(),
				)
			}
		}
	}

	return details, nil
}

// buildGetTrustedRootFn returns a getTrustedRootFn that loads from a local file when trustedRootPath
// is set (custom/private Sigstore instance), or fetches from the public TUF repository otherwise.
func buildGetTrustedRootFn(trustedRootPath string) getTrustedRootFn {
	if trustedRootPath != "" {
		return func() (sgroot.TrustedMaterial, error) {
			tr, err := sgroot.NewTrustedRootFromPath(trustedRootPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load trusted root from %q: %w", trustedRootPath, err)
			}
			return tr, nil
		}
	}
	return func() (sgroot.TrustedMaterial, error) {
		return sgroot.FetchTrustedRoot()
	}
}

func cosignIdentityToSGVerify(identity cosign.Identity) (sgverify.CertificateIdentity, error) {
	sanMatcher, err := sgverify.NewSANMatcher(identity.Subject, identity.SubjectRegExp)
	if err != nil {
		return sgverify.CertificateIdentity{}, fmt.Errorf("invalid SAN matcher: %w", err)
	}
	issuerMatcher, err := sgverify.NewIssuerMatcher(identity.Issuer, identity.IssuerRegExp)
	if err != nil {
		return sgverify.CertificateIdentity{}, fmt.Errorf("invalid issuer matcher: %w", err)
	}
	// Empty Extensions{} means no extra OCI extension constraints are required beyond SAN and
	// issuer. cosign.Identity has no extension fields so this is intentionally unconstrained.
	return sgverify.NewCertificateIdentity(sanMatcher, issuerMatcher, sgcert.Extensions{})
}
