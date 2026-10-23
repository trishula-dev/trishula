package ml

import (
	"testing"
	"time"
)

// baseNow is the fixtures' clock start (a fixed epoch, timer-free).
var baseNow = time.Unix(1700000000, 0)

// fixtureClock returns an injected clock advancing by a delta per call
// site (static base; tests move it by editing the closure's variable).
func fixtureClock(now *time.Time) func() time.Time {
	return func() time.Time { return *now }
}

// TestVerdictCacheRoundTrip pins the spec's ML-hand-off verdict-cache contract: keyed
// on the normalized request signature, tag-checked by the judge model id.
func TestVerdictCacheRoundTrip(t *testing.T) {
	now := baseNow
	c, err := NewVerdictCache(fixtureClock(&now), 8, time.Hour)
	if err != nil {
		t.Fatalf("NewVerdictCache: %v", err)
	}
	v := JudgeVerdict{Label: "prompt-injection", ModelID: "j1", Confidence: 0.9, Reason: "r1"}
	c.Put("sig1", "j1", v)
	got, ok := c.Get("sig1", "j1")
	if !ok {
		t.Fatal("Get: miss for the cached, tag-matching verdict")
	}
	if got.Label != "prompt-injection" || got.ModelID != "j1" || got.Confidence != 0.9 {
		t.Errorf("Get: got %+v, want the cached verdict %+v", got, v)
	}
	if _, ok := c.Get("sig1", "j2"); ok {
		t.Error("Get: model-mismatched read returned hit (the model tag must gate)")
	}
	if c.Len() != 1 {
		t.Errorf("Len: got %d, want 1", c.Len())
	}
}

// TestVerdictCacheTTL pins the TTL contract: a hit at age < ttl, a miss at
// age >= ttl (the loader-expiry parity convention).
func TestVerdictCacheTTL(t *testing.T) {
	now := baseNow
	c, err := NewVerdictCache(fixtureClock(&now), 8, time.Hour)
	if err != nil {
		t.Fatalf("NewVerdictCache: %v", err)
	}
	c.Put("sig1", "j1", JudgeVerdict{Label: "benign", ModelID: "j1"})
	now = baseNow.Add(time.Minute) // well inside the TTL
	if _, ok := c.Get("sig1", "j1"); !ok {
		t.Error("Get: miss at age < ttl")
	}
	now = baseNow.Add(time.Hour) // exactly the TTL: expired (age >= ttl)
	if _, ok := c.Get("sig1", "j1"); ok {
		t.Error("Get: hit at age >= ttl")
	}
	if c.Len() != 0 {
		t.Errorf("Len: got %d, want 0 (expired entries leave the cache)", c.Len())
	}
}

// TestVerdictCacheLRUCap pins the eviction order: least recently USED —
// read-touches refresh the recency.
func TestVerdictCacheLRUCap(t *testing.T) {
	now := baseNow
	c, err := NewVerdictCache(fixtureClock(&now), 2, time.Hour)
	if err != nil {
		t.Fatalf("NewVerdictCache: %v", err)
	}
	c.Put("k1", "j1", JudgeVerdict{Label: "l1", ModelID: "j1"})
	c.Put("k2", "j1", JudgeVerdict{Label: "l2", ModelID: "j1"})
	if _, ok := c.Get("k1", "j1"); !ok { // touch: k1 turns MRU
		t.Fatal("Get: k1 miss before the eviction row")
	}
	c.Put("k3", "j1", JudgeVerdict{Label: "l3", ModelID: "j1"})
	if _, ok := c.Get("k2", "j1"); ok {
		t.Error("Get: k2 hit after eviction (wanted LRU-evicted)")
	}
	if _, ok := c.Get("k1", "j1"); !ok {
		t.Error("Get: k1 miss (wanted the read-touch to survive eviction)")
	}
	if _, ok := c.Get("k3", "j1"); !ok {
		t.Error("Get: k3 miss")
	}
}

// TestVerdictCacheValidates pins the wiring-error rows on the constructor.
func TestVerdictCacheValidates(t *testing.T) {
	now := baseNow
	rows := []struct {
		name   string
		clock  func() time.Time
		cap    int
		ttl    time.Duration
		wantOk bool
	}{
		{"nil clock", nil, 2, time.Hour, false},
		{"zero cap", fixtureClock(&now), 0, time.Hour, false},
		{"negative ttl", fixtureClock(&now), 2, -time.Hour, false},
		{"valid", fixtureClock(&now), 2, time.Hour, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := NewVerdictCache(r.clock, r.cap, r.ttl)
			if (err == nil) != r.wantOk {
				t.Errorf("NewVerdictCache: err=%v, wantOk=%v", err, r.wantOk)
			}
		})
	}
}
