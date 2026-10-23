// cache.go carries the §14.2 verdict cache (TR-21 v0 = the judge-verdict
// cache): an LRU keyed on the normalized request signature, TTL'd and
// judge-model tagged (§14.2 item 4: "always async and suspicious-only,
// with verdicts cached (TTL 24 h default)"). High-confidence verdicts
// write back to kernel maps in a later slice (§13.3 loop closure) — v0
// keeps the cache userspace-only.
package ml

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// VerdictCache is the §14.2 verdict cache: LRU, TTL'd, model-tagged.
type VerdictCache struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	now  func() time.Time
	ents map[string]*cacheEntry
	lru  *list.List // front = most recently used; element value = the signature
}

// cacheEntry is one cached judgement: verdict + tag + stamp.
type cacheEntry struct {
	sig     string
	modelID string
	at      time.Time
	v       JudgeVerdict
	el      *list.Element
}

// NewVerdictCache builds the cache on an injected clock, a positive entry
// cap and a positive TTL (the wiring contract: every tunable arrives
// injected — a nil clock is a wiring error, never a guessed wall clock).
func NewVerdictCache(now func() time.Time, maxEntries int, ttl time.Duration) (*VerdictCache, error) {
	if now == nil {
		return nil, fmt.Errorf("verdict cache: nil clock")
	}
	if maxEntries <= 0 {
		return nil, fmt.Errorf("verdict cache: maxEntries %d must be positive", maxEntries)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("verdict cache: ttl %s must be positive", ttl)
	}
	return &VerdictCache{
		max:  maxEntries,
		ttl:  ttl,
		now:  now,
		ents: make(map[string]*cacheEntry),
		lru:  list.New(),
	}, nil
}

// Get returns the cached verdict for a signature when it is fresh (age
// strictly under the TTL) and tagged to modelID; otherwise miss. A
// model-mismatched read is a miss that leaves the entry in place; an
// expired read evicts the entry. Fresh hits move the entry to MRU.
func (c *VerdictCache) Get(sig, modelID string) (JudgeVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.ents[sig]
	if !ok {
		return JudgeVerdict{}, false
	}
	if c.now().Sub(e.at) >= c.ttl { // loader-expiry parity: age >= ttl is expired
		c.lru.Remove(e.el)
		delete(c.ents, sig)
		return JudgeVerdict{}, false
	}
	if e.modelID != modelID {
		return JudgeVerdict{}, false
	}
	c.lru.MoveToFront(e.el)
	return e.v, true
}

// Put caches the verdict under its signature + model tag. A re-put
// refreshes the entry in place and moves it to MRU.
func (c *VerdictCache) Put(sig, modelID string, v JudgeVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.ents[sig]; ok {
		e.modelID, e.v, e.at = modelID, v, now
		c.lru.MoveToFront(e.el)
		return
	}
	e := &cacheEntry{sig: sig, modelID: modelID, at: now, v: v}
	e.el = c.lru.PushFront(sig) // element values are signatures (the eviction cast)
	c.ents[sig] = e
	for len(c.ents) > c.max {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.lru.Remove(back)
		delete(c.ents, back.Value.(string))
	}
}

// Len reports the live (unexpired) entry count.
func (c *VerdictCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	n := 0
	for _, e := range c.ents {
		if now.Sub(e.at) < c.ttl {
			n++
		}
	}
	return n
}
