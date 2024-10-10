package cache

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/agent"
)

type JWTSVIDCache struct {
	log     logrus.FieldLogger
	metrics telemetry.Metrics
	mu      sync.RWMutex
	svids   map[string]*client.JWTSVID
}

func (c *JWTSVIDCache) CountJWTSVIDs() int {
	return len(c.svids)
}

func NewJWTSVIDCache(log logrus.FieldLogger, metrics telemetry.Metrics) *JWTSVIDCache {
	return &JWTSVIDCache{
		metrics: metrics,
		log:     log,
		svids:   make(map[string]*client.JWTSVID),
	}
}

func (c *JWTSVIDCache) GetJWTSVID(spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, bool) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()
	svid, ok := c.svids[key]
	return svid, ok
}

func (c *JWTSVIDCache) SetJWTSVID(spiffeID spiffeid.ID, audience []string, svid *client.JWTSVID) {
	key := jwtSVIDKey(spiffeID, audience)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.svids[key] = svid
}

func (c *JWTSVIDCache) TaintJWTSVIDs(ctx context.Context, taintedJWTAuthorities map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	counter := telemetry.StartCall(c.metrics, telemetry.CacheManager, agent.CacheTypeWorkload, telemetry.ProcessTaintedJWTSVIDs)
	defer counter.Done(nil)

	var taintedKeyIDs []string
	svidsRemoved := 0
	for key, jwtSVID := range c.svids {
		if _, tainted := taintedJWTAuthorities[jwtSVID.Kid]; tainted {
			delete(c.svids, key)
			taintedKeyIDs = append(taintedKeyIDs, jwtSVID.Kid)
			svidsRemoved++
		}
		select {
		case <-ctx.Done():
			c.log.WithError(ctx.Err()).Warn("Context cancelled, exiting process of tainting JWT-SVIDs in cache")
			return
		default:
		}
	}
	taintedKeyIDsCount := len(taintedKeyIDs)
	if taintedKeyIDsCount > 0 {
		c.log.WithField(telemetry.JWTAuthorityKeyIDs, strings.Join(taintedKeyIDs, ",")).
			WithField(telemetry.CountJWTSVIDs, svidsRemoved).
			Info("JWT-SVIDs were removed from the JWT cache because they were issued by a tainted authority")
	}
	agent.AddCacheManagerTaintedJWTSVIDsSample(c.metrics, agent.CacheTypeWorkload, float32(taintedKeyIDsCount))
}

func jwtSVIDKey(spiffeID spiffeid.ID, audience []string) string {
	h := sha256.New()

	// Form the cache key as the SHA-256 hash of the SPIFFE ID and all the audiences.
	// In order to avoid ambiguities, we will write a nul byte to the hash function after each data
	// item.

	// duplicate and sort the audience slice
	audience = append([]string(nil), audience...)
	sort.Strings(audience)

	_, _ = io.WriteString(h, spiffeID.String())
	h.Write([]byte{0})
	for _, a := range audience {
		_, _ = io.WriteString(h, a)
		h.Write([]byte{0})
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
