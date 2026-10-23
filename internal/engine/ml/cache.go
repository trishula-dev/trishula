// cache.go carries the §14.2 verdict cache (TR-21 v0 = the judge-verdict
// cache): an LRU keyed on the normalized request signature, TTL'd and
// judge-model tagged (§14.2 item 4: "always async and suspicious-only,
// with verdicts cached (TTL 24 h default)"). High-confidence verdicts
// write back to kernel maps in a later slice (§13.3 loop closure) — v0
// keeps the cache userspace-only.
package ml

import (
	"time"
)

// VerdictCache is the §14.2 verdict cache: LRU, TTL'd, model-tagged.
type VerdictCache struct{}

// NewVerdictCache builds the cache on an injected clock, a positive entry
// cap and a positive TTL (the wiring contract: every tunable arrives
// injected — a nil clock is a wiring error, never a guessed wall clock).
func NewVerdictCache(now func() time.Time, maxEntries int, ttl time.Duration) (*VerdictCache, error) {
	return &VerdictCache{}, nil // TR-21 RED stub
}

// Get returns the cached verdict for a signature when it is fresh (age
// strictly under the TTL) and tagged to modelID; otherwise miss. A
// model-mismatched read is a miss that leaves the entry in place.
func (c *VerdictCache) Get(sig, modelID string) (JudgeVerdict, bool) {
	return JudgeVerdict{}, false // TR-21 RED stub
}

// Put caches the verdict under its signature + model tag.
func (c *VerdictCache) Put(sig, modelID string, v JudgeVerdict) {}

// Len reports the live (unexpired) entry count.
func (c *VerdictCache) Len() int { return 0 } // TR-21 RED stub
