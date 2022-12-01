package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"reflect"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type JWTSVIDCache struct {
	mu    sync.Mutex
	svids map[string]*client.JWTSVID

	taintedKeys map[string]struct{}
}

func NewJWTSVIDCache() *JWTSVIDCache {
	return &JWTSVIDCache{
		svids: make(map[string]*client.JWTSVID),
	}
}

func (c *JWTSVIDCache) ForceJWTRotation(taintedKeys map[string]struct{}, log logrus.FieldLogger) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// No new tainted keys, clean list
	if len(taintedKeys) == 0 {
		// No tainted keys reset and return
		c.taintedKeys = nil
		return nil
	}
	if reflect.DeepEqual(c.taintedKeys, taintedKeys) {
		// No changes... just return no action required
		return nil
	}

	svids := make(map[string]*client.JWTSVID)

	var removedSVIDs int
	for audience, svid := range c.svids {
		jToken, err := jwt.ParseSigned(svid.Token)
		if err != nil {
			return err
		}

		if !containsKeyID(jToken.Headers, taintedKeys) {
			svids[audience] = svid
		} else {
			removedSVIDs++
		}
	}

	log.WithField(telemetry.JWTSVID, removedSVIDs).Debug("Removed tainted JWT SVIDs")

	c.svids = svids
	c.taintedKeys = taintedKeys
	return nil
}

func containsKeyID(headers []jose.Header, taintedKeys map[string]struct{}) bool {
	for _, h := range headers {
		if h.KeyID != "" {
			_, ok := taintedKeys[h.KeyID]
			if ok {
				return true
			}
		}
	}

	return false
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

func jwtSVIDKey(spiffeID spiffeid.ID, audience []string) string {
	h := sha256.New()

	// duplicate and sort the audience slice
	audience = append([]string(nil), audience...)
	sort.Strings(audience)

	_, _ = io.WriteString(h, spiffeID.String())
	for _, a := range audience {
		_, _ = io.WriteString(h, a)
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
