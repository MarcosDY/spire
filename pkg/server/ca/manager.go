package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
)

const (
	DefaultCATTL    = 24 * time.Hour
	rotateInterval  = 10 * time.Second
	pruneInterval   = 6 * time.Hour
	safetyThreshold = 24 * time.Hour

	thirtyDays                  = 30 * 24 * time.Hour
	preparationThresholdCap     = thirtyDays
	preparationThresholdDivisor = 2

	sevenDays                  = 7 * 24 * time.Hour
	activationThresholdCap     = sevenDays
	activationThresholdDivisor = 6

	publishJWKTimeout = 5 * time.Second
)

type ManagedCA interface {
	SetX509CA(*X509CA)
	SetJWTKey(*JWTKey)
}

type ManagerConfig struct {
	CA            ManagedCA
	Catalog       catalog.Catalog
	TrustDomain   spiffeid.TrustDomain
	X509CAKeyType keymanager.KeyType
	JWTKeyType    keymanager.KeyType
	CASubject     pkix.Name
	Dir           string
	Log           logrus.FieldLogger
	Metrics       telemetry.Metrics
	Clock         clock.Clock
	HealthChecker health.Checker
}

type Manager struct {
	c ManagerConfig

	// For keeping track of number of failed rotations.
	failedRotationNum uint64

	// Used to log a warning only once when the UpstreamAuthority does not support JWT-SVIDs.
	jwtUnimplementedWarnOnce sync.Once
}

func NewManager(c ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	m := &Manager{
		c: c,
	}

	_ = c.HealthChecker.AddCheck("server.ca.manager", &managerHealth{m: m})

	return m
}

func (m *Manager) Initialize(ctx context.Context) error {
	if err := m.loadJournal(ctx); err != nil {
		return err
	}
	return m.rotate(ctx)
}

func (m *Manager) Run(ctx context.Context) error {
	// Shut down any open streams in the upstream client when the manager
	// has finished running.
	if m.upstreamClient != nil {
		defer func() { _ = m.upstreamClient.Close() }()
	}

	if err := m.notifyBundleLoaded(ctx); err != nil {
		return err
	}
	err := util.RunTasks(ctx,
		func(ctx context.Context) error {
			return m.rotateEvery(ctx, rotateInterval)
		},
		func(ctx context.Context) error {
			return m.pruneBundleEvery(ctx, pruneInterval)
		},
		func(ctx context.Context) error {
			// notifyOnBundleUpdate does not fail but rather logs any errors
			// encountered while notifying
			m.notifyOnBundleUpdate(ctx)
			return nil
		},
	)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

func (m *Manager) rotateEvery(ctx context.Context, interval time.Duration) error {
	ticker := m.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// rotate() errors are logged by rotate() and shouldn't cause the
			// manager run task to bail so ignore them here. The error returned
			// by rotate is used by the unit tests, so we need to keep it for
			// now.
			_ = m.rotate(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) rotate(ctx context.Context) error {
	x509CAErr := m.rotateX509CA(ctx)
	if x509CAErr != nil {
		atomic.AddUint64(&m.failedRotationNum, 1)
		m.c.Log.WithError(x509CAErr).Error("Unable to rotate X509 CA")
	}

	jwtKeyErr := m.rotateJWTKey(ctx)
	if jwtKeyErr != nil {
		atomic.AddUint64(&m.failedRotationNum, 1)
		m.c.Log.WithError(jwtKeyErr).Error("Unable to rotate JWT key")
	}

	return errs.Combine(x509CAErr, jwtKeyErr)
}

func (m *Manager) rotateX509CA(ctx context.Context) error {
	now := m.c.Clock.Now()

	// if there is no current keypair set, generate one
	if m.currentX509CA.IsEmpty() {
		if err := m.prepareX509CA(ctx, m.currentX509CA); err != nil {
			return err
		}
		m.activateX509CA()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if m.nextX509CA.IsEmpty() && m.currentX509CA.ShouldPrepareNext(now) {
		if err := m.prepareX509CA(ctx, m.nextX509CA); err != nil {
			return err
		}
	}

	if m.currentX509CA.ShouldActivateNext(now) {
		m.currentX509CA, m.nextX509CA = m.nextX509CA, m.currentX509CA
		m.nextX509CA.Reset()
		m.activateX509CA()
	}

	return nil
}

func (m *Manager) failedRotationResult() uint64 {
	return atomic.LoadUint64(&m.failedRotationNum)
}

func (m *Manager) rotateJWTKey(ctx context.Context) error {
	now := m.c.Clock.Now()

	// if there is no current keypair set, generate one
	if m.currentJWTKey.IsEmpty() {
		if err := m.prepareJWTKey(ctx, m.currentJWTKey); err != nil {
			return err
		}
		m.activateJWTKey()
	}

	// if there is no next keypair set and the current is within the
	// preparation threshold, generate one.
	if m.nextJWTKey.IsEmpty() && m.currentJWTKey.ShouldPrepareNext(now) {
		if err := m.prepareJWTKey(ctx, m.nextJWTKey); err != nil {
			return err
		}
	}

	if m.currentJWTKey.ShouldActivateNext(now) {
		m.currentJWTKey, m.nextJWTKey = m.nextJWTKey, m.currentJWTKey
		m.nextJWTKey.Reset()
		m.activateJWTKey()
	}

	return nil
}

func (m *Manager) pruneBundleEvery(ctx context.Context, interval time.Duration) error {
	ticker := m.c.Clock.Ticker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.pruneBundle(ctx); err != nil {
				m.c.Log.WithError(err).Error("Could not prune CA certificates")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) pruneBundle(ctx context.Context) (err error) {
	counter := telemetry_server.StartCAManagerPruneBundleCall(m.c.Metrics)
	defer counter.Done(&err)

	ds := m.c.Catalog.GetDataStore()
	expiresBefore := m.c.Clock.Now().Add(-safetyThreshold)

	changed, err := ds.PruneBundle(ctx, m.c.TrustDomain.IDString(), expiresBefore)

	if err != nil {
		return fmt.Errorf("unable to prune bundle: %w", err)
	}

	if changed {
		telemetry_server.IncrManagerPrunedBundleCounter(m.c.Metrics)
		m.c.Log.Debug("Expired certificates were successfully pruned from bundle")
		m.bundleUpdated()
	}

	return nil
}

func (m *Manager) appendBundle(ctx context.Context, caChain []*x509.Certificate, jwtSigningKeys []*common.PublicKey) (*common.Bundle, error) {
	var rootCAs []*common.Certificate
	for _, caCert := range caChain {
		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: caCert.Raw,
		})
	}

	ds := m.c.Catalog.GetDataStore()
	res, err := ds.AppendBundle(ctx, &common.Bundle{
		TrustDomainId:  m.c.TrustDomain.IDString(),
		RootCas:        rootCAs,
		JwtSigningKeys: jwtSigningKeys,
	})
	if err != nil {
		return nil, err
	}

	m.bundleUpdated()
	return res, nil
}

func (m *Manager) notifyOnBundleUpdate(ctx context.Context) {
	for {
		select {
		case <-m.bundleUpdatedCh:
			if err := m.notifyBundleUpdated(ctx); err != nil {
				m.c.Log.WithError(err).Warn("Failed to notify on bundle update")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) notifyBundleLoaded(ctx context.Context) error {
	// if initialization has triggered a "bundle updated" event (e.g. server CA
	// was rotated), we want to drain it now as we're about to emit the initial
	// bundle loaded event.  otherwise, plugins will get an immediate "bundle
	// updated" event right after "bundle loaded".
	m.dropBundleUpdated()

	var bundle *common.Bundle
	return m.notify(ctx, "bundle loaded", true,
		func(ctx context.Context) (err error) {
			bundle, err = m.fetchRequiredBundle(ctx)
			return err
		},
		func(ctx context.Context, n notifier.Notifier) error {
			return n.NotifyAndAdviseBundleLoaded(ctx, bundle)
		},
	)
}

func (m *Manager) notifyBundleUpdated(ctx context.Context) error {
	var bundle *common.Bundle
	return m.notify(ctx, "bundle updated", false,
		func(ctx context.Context) (err error) {
			bundle, err = m.fetchRequiredBundle(ctx)
			return err
		},
		func(ctx context.Context, n notifier.Notifier) error {
			return n.NotifyBundleUpdated(ctx, bundle)
		},
	)
}

func (m *Manager) notify(ctx context.Context, event string, advise bool, pre func(context.Context) error, do func(context.Context, notifier.Notifier) error) error {
	notifiers := m.c.Catalog.GetNotifiers()
	if len(notifiers) == 0 {
		return nil
	}

	if pre != nil {
		if err := pre(ctx); err != nil {
			return err
		}
	}

	errsCh := make(chan error, len(notifiers))
	for _, n := range notifiers {
		go func(n notifier.Notifier) {
			err := do(ctx, n)
			f := m.c.Log.WithFields(logrus.Fields{
				telemetry.Notifier: n.Name(),
				telemetry.Event:    event,
			})
			if err == nil {
				f.Debug("Notifier handled event")
			} else {
				f := f.WithError(err)
				if advise {
					f.Error("Notifier failed to handle event")
				} else {
					f.Warn("Notifier failed to handle event")
				}
			}
			errsCh <- err
		}(n)
	}

	var allErrs errs.Group
	for i := 0; i < len(notifiers); i++ {
		// don't select on the ctx here as we can rely on the plugins to
		// respond to context cancelation and return an error.
		if err := <-errsCh; err != nil {
			allErrs.Add(err)
		}
	}
	if err := allErrs.Err(); err != nil {
		return errs.New("one or more notifiers returned an error: %v", err)
	}
	return nil
}

// filterInvalidEntries takes in a set of journal entries, and removes entries that represent signing keys
// that do not appear in the bundle from the datastore. This prevents SPIRE from entering strange
// and inconsistent states as a result of key mismatch following things like database restore,
// disk/journal manipulation, etc.
//
// If we find such a discrepancy, removing the entry from the journal prior to beginning signing
// operations prevents us from using a signing key that consumers may not be able to validate.
// Instead, we'll rotate into a new one.
func (m *Manager) filterInvalidEntries(ctx context.Context, entries *journal.Entries) ([]*JWTKeyEntry, []*X509CAEntry, error) {
	bundle, err := m.fetchOptionalBundle(ctx)

	if err != nil {
		return nil, nil, err
	}

	if bundle == nil {
		return entries.JwtKeys, entries.X509CAs, nil
	}

	filteredEntriesJwtKeys := []*JWTKeyEntry{}

	for _, entry := range entries.GetJwtKeys() {
		if containsJwtSigningKeyid(bundle.JwtSigningKeys, entry.Kid) {
			filteredEntriesJwtKeys = append(filteredEntriesJwtKeys, entry)
			continue
		}
	}

	// If we have an upstream authority then we're not recovering a root CA, so we do
	// not expect to find our CA certificate in the bundle. Simply proceed.
	if m.upstreamClient != nil {
		return filteredEntriesJwtKeys, entries.X509CAs, nil
	}

	filteredEntriesX509CAs := []*X509CAEntry{}

	for _, entry := range entries.GetX509CAs() {
		if containsX509CA(bundle.RootCas, entry.Certificate) {
			filteredEntriesX509CAs = append(filteredEntriesX509CAs, entry)
			continue
		}
	}

	return filteredEntriesJwtKeys, filteredEntriesX509CAs, nil
}

func (m *Manager) fetchRequiredBundle(ctx context.Context) (*common.Bundle, error) {
	bundle, err := m.fetchOptionalBundle(ctx)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, errs.New("trust domain bundle is missing")
	}
	return bundle, nil
}

func (m *Manager) fetchOptionalBundle(ctx context.Context) (*common.Bundle, error) {
	ds := m.c.Catalog.GetDataStore()
	bundle, err := ds.FetchBundle(ctx, m.c.TrustDomain.IDString())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return bundle, nil
}

func x509CAKmKeyID(id string) string {
	return fmt.Sprintf("x509-CA-%s", id)
}

func jwtKeyKmKeyID(id string) string {
	return fmt.Sprintf("JWT-Signer-%s", id)
}

func otherSlotID(id string) string {
	if id == "A" {
		return "B"
	}
	return "A"
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	matches, err := cryptoutil.PublicKeyEqual(a, b)
	if err != nil {
		return false
	}
	return matches
}

// MaxSVIDTTL returns the maximum SVID lifetime that can be guaranteed to not
// be cut artificially short by a scheduled rotation.
func MaxSVIDTTL() time.Duration {
	return activationThresholdCap
}

// MaxSVIDTTLForCATTL returns the maximum SVID TTL that can be guaranteed given
// a specific CA TTL. In other words, given a CA TTL, what is the largest SVID
// TTL that is guaranteed to not be cut artificially short by a scheduled
// rotation?
func MaxSVIDTTLForCATTL(caTTL time.Duration) time.Duration {
	maxTTL := caTTL / activationThresholdDivisor
	if maxTTL > activationThresholdCap {
		maxTTL = activationThresholdCap
	}

	return maxTTL
}

// MinCATTLForSVIDTTL returns the minimum CA TTL necessary to guarantee an SVID
// TTL of the provided value. In other words, given an SVID TTL, what is the
// minimum CA TTL that will guarantee that the SVIDs lifetime won't be cut
// artificially short by a scheduled rotation?
func MinCATTLForSVIDTTL(svidTTL time.Duration) time.Duration {
	return svidTTL * activationThresholdDivisor
}

func preparationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	threshold := lifetime / preparationThresholdDivisor
	if threshold > preparationThresholdCap {
		threshold = preparationThresholdCap
	}
	return notAfter.Add(-threshold)
}

func keyActivationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	threshold := lifetime / activationThresholdDivisor
	if threshold > activationThresholdCap {
		threshold = activationThresholdCap
	}
	return notAfter.Add(-threshold)
}

func newKeyID() (string, error) {
	choices := make([]byte, 32)
	_, err := rand.Read(choices)
	if err != nil {
		return "", err
	}
	return keyIDFromBytes(choices), nil
}

func keyIDFromBytes(choices []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := new(bytes.Buffer)
	for _, choice := range choices {
		buf.WriteByte(alphabet[int(choice)%len(alphabet)])
	}
	return buf.String()
}

func containsJwtSigningKeyid(keys []*common.PublicKey, kid string) bool {
	for _, key := range keys {
		if key.Kid == kid {
			return true
		}
	}

	return false
}

func containsX509CA(rootCAs []*common.Certificate, certificate []byte) bool {
	for _, ca := range rootCAs {
		if bytes.Equal(ca.DerBytes, certificate) {
			return true
		}
	}
	return false
}
