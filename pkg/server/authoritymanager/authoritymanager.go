package authoritymanager

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"path/filepath"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DefaultCATTL = 24 * time.Hour
	backdate     = 10 * time.Second
)

type KeyStatus int

const (
	KeyStatusUnset KeyStatus = iota
	Active
	Prepared
	Old
)

type KeyState struct {
	Status    KeyStatus
	PublicKey crypto.PublicKey
}

type Config struct {
	TrustDomain   spiffeid.TrustDomain
	Catalog       catalog.Catalog
	CATTL         time.Duration
	Clock         clock.Clock
	Metrics       telemetry.Metrics
	Log           logrus.FieldLogger
	X509CAKeyType keymanager.KeyType
	JWTKeyType    keymanager.KeyType
}

type Manager interface {
	PrepareJWTKey(ctx context.Context, slot *jwtKeySlot) (err error)
	PrepareX509CA(ctx context.Context, slot *x509CASlot) (err error)
	ActivateX509CA()
	ActivateJWTKey()

	PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error)

	BundleUpdated()
	DropBundleUpdated()
}

func NewManager(c Config) Manager {
	if c.CATTL <= 0 {
		c.CATTL = DefaultCATTL
	}

	if c.Clock == nil {
		c.Clock = clock.New()
	}

	m := &manager{
		bundleUpdatedCh: make(chan struct{}, 1),
	}

	if upstreamAuthority, ok := c.Catalog.GetUpstreamAuthority(); ok {
		m.upstreamClient = NewUpstreamClient(UpstreamClientConfig{
			UpstreamAuthority: upstreamAuthority,
			BundleUpdater: &bundleUpdater{
				log:           c.Log,
				trustDomainID: c.TrustDomain.IDString(),
				ds:            c.Catalog.GetDataStore(),
				updated:       m.BundleUpdated,
			},
		})
		m.upstreamPluginName = upstreamAuthority.Name()
	}

	return m
}

type manager struct {
	c Config

	currentX509CA *x509CASlot
	nextX509CA    *x509CASlot
	currentJWTKey *jwtKeySlot
	nextJWTKey    *jwtKeySlot

	bundleUpdatedCh    chan struct{}
	journal            *Journal
	upstreamClient     *UpstreamClient
	upstreamPluginName string
}

func (m *manager) PrepareJWTKey(ctx context.Context, slot *jwtKeySlot) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareJWTKeyCall(m.c.Metrics)
	defer counter.Done(&err)

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing JWT key")

	slot.Reset()

	now := m.c.Clock.Now()
	notAfter := now.Add(m.c.CATTL)

	km := m.c.Catalog.GetKeyManager()
	signer, err := km.GenerateKey(ctx, slot.KmKeyID(), m.c.JWTKeyType)
	if err != nil {
		return err
	}

	jwtKey, err := newJWTKey(signer, notAfter)
	if err != nil {
		return err
	}

	publicKey, err := publicKeyFromJWTKey(jwtKey)
	if err != nil {
		return err
	}

	// TODO: move publishKey out of manage
	if _, err := m.PublishJWTKey(ctx, publicKey); err != nil {
		return err
	}

	slot.issuedAt = now
	slot.jwtKey = jwtKey

	if err := m.journal.AppendJWTKey(slot.id, slot.issuedAt, slot.jwtKey); err != nil {
		log.WithError(err).Error("Unable to append JWT key to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       slot.id,
		telemetry.IssuedAt:   slot.issuedAt,
		telemetry.Expiration: slot.jwtKey.NotAfter,
	}).Info("JWT key prepared")
	return nil
}

func (m *manager) PrepareX509CA(ctx context.Context, slot *x509CASlot) (err error) {
	counter := telemetry_server.StartServerCAManagerPrepareX509CACall(m.c.Metrics)
	defer counter.Done(&err)

	log := m.c.Log.WithField(telemetry.Slot, slot.id)
	log.Debug("Preparing X509 CA")

	slot.Reset()

	now := m.c.Clock.Now()
	km := m.c.Catalog.GetKeyManager()
	signer, err := km.GenerateKey(ctx, slot.KmKeyID(), m.c.X509CAKeyType)
	if err != nil {
		return err
	}

	var x509CA *X509CA
	if m.upstreamClient != nil {
		x509CA, err = UpstreamSignX509CA(ctx, signer, m.c.TrustDomain, m.c.CASubject, m.upstreamClient, m.c.CATTL)
		if err != nil {
			return err
		}
	} else {
		notBefore := now.Add(-backdate)
		notAfter := now.Add(m.c.CATTL)
		var trustBundle []*x509.Certificate
		x509CA, trustBundle, err = SelfSignX509CA(ctx, signer, m.c.TrustDomain, m.c.CASubject, notBefore, notAfter)
		if err != nil {
			return err
		}
		if _, err := m.appendBundle(ctx, trustBundle, nil); err != nil {
			return err
		}
	}

	slot.issuedAt = now
	slot.x509CA = x509CA

	if err := m.journal.AppendX509CA(slot.id, slot.issuedAt, slot.x509CA); err != nil {
		log.WithError(err).Error("Unable to append X509 CA to journal")
	}

	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       slot.id,
		telemetry.IssuedAt:   slot.issuedAt,
		telemetry.Expiration: slot.x509CA.Certificate.NotAfter,
		telemetry.SelfSigned: m.upstreamClient == nil,
	}).Info("X509 CA prepared")
	return nil
}

// PublishJWTKey publishes the passed JWK to the upstream server using the configured
// UpstreamAuthority plugin, then appends to the bundle the JWKs returned by the upstream server,
// and finally it returns the updated list of JWT keys contained in the bundle.
//
// The following cases may arise when calling this function:
//
// - The UpstreamAuthority plugin doesn't implement PublishJWTKey, in which case we receive an
// Unimplemented error from the upstream server, and hence we log a one time warning about this,
// append the passed JWK to the bundle, and return the updated list of JWT keys.
//
// - The UpstreamAuthority plugin returned an error, then we return the error.
//
// - There is no UpstreamAuthority plugin configured, then assumes we are the root server and
// just appends the passed JWK to the bundle and returns the updated list of JWT keys.
func (m *manager) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error) {
	if m.upstreamClient != nil {
		publishCtx, cancel := context.WithTimeout(ctx, publishJWKTimeout)
		defer cancel()
		upstreamJWTKeys, err := m.upstreamClient.PublishJWTKey(publishCtx, jwtKey)
		switch {
		case status.Code(err) == codes.Unimplemented:
			// JWT Key publishing is not supported by the upstream plugin.
			// Issue a one-time warning and then fall through to the
			// appendBundle call below as if an upstream client was not
			// configured so the JWT key gets pushed into the local bundle.
			m.jwtUnimplementedWarnOnce.Do(func() {
				m.c.Log.WithField("plugin_name", m.upstreamPluginName).Warn("UpstreamAuthority plugin does not support JWT-SVIDs. Workloads managed " +
					"by this server may have trouble communicating with workloads outside " +
					"this cluster when using JWT-SVIDs.")
			})
		case err != nil:
			return nil, err
		default:
			return upstreamJWTKeys, nil
		}
	}

	bundle, err := m.appendBundle(ctx, nil, []*common.PublicKey{jwtKey})
	if err != nil {
		return nil, err
	}

	return bundle.JwtSigningKeys, nil
}

func (m *manager) ActivateX509CA() {
	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       m.currentX509CA.id,
		telemetry.IssuedAt:   m.currentX509CA.issuedAt,
		telemetry.Expiration: m.currentX509CA.x509CA.Certificate.NotAfter,
	}).Info("X509 CA activated")
	telemetry_server.IncrActivateX509CAManagerCounter(m.c.Metrics)

	ttl := m.currentX509CA.x509CA.Certificate.NotAfter.Sub(m.c.Clock.Now())
	telemetry_server.SetX509CARotateGauge(m.c.Metrics, m.c.TrustDomain.String(), float32(ttl.Seconds()))
	m.c.Log.WithFields(logrus.Fields{
		telemetry.TrustDomainID: m.c.TrustDomain.IDString(),
		telemetry.TTL:           ttl.Seconds(),
	}).Debug("Successfully rotated X.509 CA")

	m.c.CA.SetX509CA(m.currentX509CA.x509CA)
}

func (m *manager) BundleUpdated() {
	select {
	case m.bundleUpdatedCh <- struct{}{}:
	default:
	}
}

func (m *manager) DropBundleUpdated() {
	select {
	case <-m.bundleUpdatedCh:
	default:
	}
}

func (m *manager) ActivateJWTKey() {
	m.c.Log.WithFields(logrus.Fields{
		telemetry.Slot:       m.currentJWTKey.id,
		telemetry.IssuedAt:   m.currentJWTKey.issuedAt,
		telemetry.Expiration: m.currentJWTKey.jwtKey.NotAfter,
	}).Info("JWT key activated")
	telemetry_server.IncrActivateJWTKeyManagerCounter(m.c.Metrics)
	m.c.CA.SetJWTKey(m.currentJWTKey.jwtKey)
}

func (m *manager) loadJournal(ctx context.Context) error {
	jsonPath := filepath.Join(m.c.Dir, "certs.json")
	if ok, err := migrateJSONFile(jsonPath, m.journalPath()); err != nil {
		return errs.New("failed to migrate old JSON data: %v", err)
	} else if ok {
		m.c.Log.Info("Migrated data to journal")
	}

	// Load the journal and see if we can figure out the next and current
	// X509CA and JWTKey entries, if any.
	m.c.Log.WithField(telemetry.Path, m.journalPath()).Debug("Loading journal")
	journal, err := LoadJournal(m.journalPath())
	if err != nil {
		return err
	}

	m.journal = journal

	entries := journal.Entries()

	now := m.c.Clock.Now()

	m.c.Log.WithFields(logrus.Fields{
		telemetry.X509CAs: len(entries.X509CAs),
		telemetry.JWTKeys: len(entries.JwtKeys),
	}).Info("Journal loaded")

	// filter out local JwtKeys and X509CAs that do not exist in the database bundle
	entries.JwtKeys, entries.X509CAs, err = m.filterInvalidEntries(ctx, entries)
	if err != nil {
		return err
	}

	if len(entries.X509CAs) > 0 {
		m.nextX509CA, err = m.tryLoadX509CASlotFromEntry(ctx, entries.X509CAs[len(entries.X509CAs)-1])
		if err != nil {
			return err
		}
		// if the last entry is ok, then consider the next entry
		if m.nextX509CA != nil && len(entries.X509CAs) > 1 {
			m.currentX509CA, err = m.tryLoadX509CASlotFromEntry(ctx, entries.X509CAs[len(entries.X509CAs)-2])
			if err != nil {
				return err
			}
		}
	}
	switch {
	case m.currentX509CA != nil:
		// both current and next are set
	case m.nextX509CA != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		m.currentX509CA, m.nextX509CA = m.nextX509CA, newX509CASlot(otherSlotID(m.nextX509CA.id))
	default:
		// neither are set. initialize them with empty slots.
		m.currentX509CA = newX509CASlot("A")
		m.nextX509CA = newX509CASlot("B")
	}

	if !m.currentX509CA.IsEmpty() && !m.currentX509CA.ShouldActivateNext(now) {
		// activate the X509CA immediately if it is set and not within
		// activation time of the next X509CA.
		m.activateX509CA()
	}

	if len(entries.JwtKeys) > 0 {
		m.nextJWTKey, err = m.tryLoadJWTKeySlotFromEntry(ctx, entries.JwtKeys[len(entries.JwtKeys)-1])
		if err != nil {
			return err
		}
		// if the last entry is ok, then consider the next entry
		if m.nextJWTKey != nil && len(entries.JwtKeys) > 1 {
			m.currentJWTKey, err = m.tryLoadJWTKeySlotFromEntry(ctx, entries.JwtKeys[len(entries.JwtKeys)-2])
			if err != nil {
				return err
			}
		}
	}
	switch {
	case m.currentJWTKey != nil:
		// both current and next are set
	case m.nextJWTKey != nil:
		// next is set but not current. swap them and initialize next with an empty slot.
		m.currentJWTKey, m.nextJWTKey = m.nextJWTKey, newJWTKeySlot(otherSlotID(m.nextJWTKey.id))
	default:
		// neither are set. initialize them with empty slots.
		m.currentJWTKey = newJWTKeySlot("A")
		m.nextJWTKey = newJWTKeySlot("B")
	}

	if !m.currentJWTKey.IsEmpty() && !m.currentJWTKey.ShouldActivateNext(now) {
		// activate the JWT key immediately if it is set and not within
		// activation time of the next JWT key.
		m.activateJWTKey()
	}

	return nil
}

func (m *manager) tryLoadX509CASlotFromEntry(ctx context.Context, entry *X509CAEntry) (*x509CASlot, error) {
	slot, badReason, err := m.loadX509CASlotFromEntry(ctx, entry)
	if err != nil {
		m.c.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Error("X509CA slot failed to load")
		return nil, err
	}
	if badReason != "" {
		m.c.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Warn("X509CA slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (m *manager) loadX509CASlotFromEntry(ctx context.Context, entry *X509CAEntry) (*x509CASlot, string, error) {
	if entry.SlotId == "" {
		return nil, "no slot id", nil
	}

	cert, err := x509.ParseCertificate(entry.Certificate)
	if err != nil {
		return nil, "", errs.New("unable to parse CA certificate: %v", err)
	}

	var upstreamChain []*x509.Certificate
	for _, certDER := range entry.UpstreamChain {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, "", errs.New("unable to parse upstream chain certificate: %v", err)
		}
		upstreamChain = append(upstreamChain, cert)
	}

	signer, err := m.makeSigner(ctx, x509CAKmKeyID(entry.SlotId))
	if err != nil {
		return nil, "", err
	}

	switch {
	case signer == nil:
		return nil, "no key manager key", nil
	case !publicKeyEqual(cert.PublicKey, signer.Public()):
		return nil, "public key does not match key manager key", nil
	}

	return &x509CASlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		x509CA: &X509CA{
			Signer:        signer,
			Certificate:   cert,
			UpstreamChain: upstreamChain,
		},
	}, "", nil
}

func (m *manager) tryLoadJWTKeySlotFromEntry(ctx context.Context, entry *JWTKeyEntry) (*jwtKeySlot, error) {
	slot, badReason, err := m.loadJWTKeySlotFromEntry(ctx, entry)
	if err != nil {
		m.c.Log.WithError(err).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Error("JWT key slot failed to load")
		return nil, err
	}
	if badReason != "" {
		m.c.Log.WithError(errors.New(badReason)).WithFields(logrus.Fields{
			telemetry.Slot: entry.SlotId,
		}).Warn("JWT key slot unusable")
		return nil, nil
	}
	return slot, nil
}

func (m *manager) loadJWTKeySlotFromEntry(ctx context.Context, entry *JWTKeyEntry) (*jwtKeySlot, string, error) {
	if entry.SlotId == "" {
		return nil, "no slot id", nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(entry.PublicKey)
	if err != nil {
		return nil, "", errs.Wrap(err)
	}

	signer, err := m.makeSigner(ctx, jwtKeyKmKeyID(entry.SlotId))
	if err != nil {
		return nil, "", err
	}

	switch {
	case signer == nil:
		return nil, "no key manager key", nil
	case !publicKeyEqual(publicKey, signer.Public()):
		return nil, "public key does not match key manager key", nil
	}

	return &jwtKeySlot{
		id:       entry.SlotId,
		issuedAt: time.Unix(entry.IssuedAt, 0),
		jwtKey: &JWTKey{
			Signer:   signer,
			NotAfter: time.Unix(entry.NotAfter, 0),
			Kid:      entry.Kid,
		},
	}, "", nil
}

func (m *manager) makeSigner(ctx context.Context, keyID string) (crypto.Signer, error) {
	km := m.c.Catalog.GetKeyManager()

	key, err := km.GetKey(ctx, keyID)
	switch status.Code(err) {
	case codes.OK:
		return key, nil
	case codes.NotFound:
		return nil, nil
	default:
		return nil, errs.Wrap(err)
	}
}

func (m *manager) journalPath() string {
	return filepath.Join(m.c.Dir, "journal.pem")
}

type x509CASlot struct {
	id       string
	issuedAt time.Time
	x509CA   *X509CA
}

func newX509CASlot(id string) *x509CASlot {
	return &x509CASlot{
		id: id,
	}
}

func (s *x509CASlot) KmKeyID() string {
	return x509CAKmKeyID(s.id)
}

func (s *x509CASlot) IsEmpty() bool {
	return s.x509CA == nil
}

func (s *x509CASlot) Reset() {
	s.x509CA = nil
}

func (s *x509CASlot) ShouldPrepareNext(now time.Time) bool {
	return s.x509CA != nil && now.After(preparationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

func (s *x509CASlot) ShouldActivateNext(now time.Time) bool {
	return s.x509CA != nil && now.After(keyActivationThreshold(s.issuedAt, s.x509CA.Certificate.NotAfter))
}

type jwtKeySlot struct {
	id       string
	issuedAt time.Time
	jwtKey   *JWTKey
}

func newJWTKeySlot(id string) *jwtKeySlot {
	return &jwtKeySlot{
		id: id,
	}
}

func (s *jwtKeySlot) KmKeyID() string {
	return jwtKeyKmKeyID(s.id)
}

func (s *jwtKeySlot) IsEmpty() bool {
	return s.jwtKey == nil
}

func (s *jwtKeySlot) Reset() {
	s.jwtKey = nil
}

func (s *jwtKeySlot) ShouldPrepareNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(preparationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func (s *jwtKeySlot) ShouldActivateNext(now time.Time) bool {
	return s.jwtKey == nil || now.After(keyActivationThreshold(s.issuedAt, s.jwtKey.NotAfter))
}

func newJWTKey(signer crypto.Signer, expiresAt time.Time) (*JWTKey, error) {
	kid, err := newKeyID()
	if err != nil {
		return nil, err
	}

	return &JWTKey{
		Signer:   signer,
		Kid:      kid,
		NotAfter: expiresAt,
	}, nil
}

func publicKeyFromJWTKey(jwtKey *JWTKey) (*common.PublicKey, error) {
	pkixBytes, err := x509.MarshalPKIXPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &common.PublicKey{
		PkixBytes: pkixBytes,
		Kid:       jwtKey.Kid,
		NotAfter:  jwtKey.NotAfter.Unix(),
	}, nil
}

type bundleUpdater struct {
	log           logrus.FieldLogger
	trustDomainID string
	ds            datastore.DataStore
	updated       func()
}

func (u *bundleUpdater) AppendX509Roots(ctx context.Context, roots []*x509.Certificate) error {
	bundle := &common.Bundle{
		TrustDomainId: u.trustDomainID,
		RootCas:       make([]*common.Certificate, 0, len(roots)),
	}

	for _, root := range roots {
		bundle.RootCas = append(bundle.RootCas, &common.Certificate{
			DerBytes: root.Raw,
		})
	}
	if _, err := u.appendBundle(ctx, bundle); err != nil {
		return err
	}
	return nil
}

func (u *bundleUpdater) AppendJWTKeys(ctx context.Context, keys []*common.PublicKey) ([]*common.PublicKey, error) {
	bundle, err := u.appendBundle(ctx, &common.Bundle{
		TrustDomainId:  u.trustDomainID,
		JwtSigningKeys: keys,
	})
	if err != nil {
		return nil, err
	}
	return bundle.JwtSigningKeys, nil
}

func (u *bundleUpdater) LogError(err error, msg string) {
	u.log.WithError(err).Error(msg)
}

func (u *bundleUpdater) appendBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	dsBundle, err := u.ds.AppendBundle(ctx, bundle)
	if err != nil {
		return nil, err
	}
	u.updated()
	return dsBundle, nil
}
