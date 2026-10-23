package botdef

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// ruleBotPace, ruleBotAuthFail and ruleBotSpread are the §12.1 behavioral
// detector ids the S5 fragment carries (ladder.Rules, walk order); each is
// one detector of the behavioral family.
const (
	ruleBotPace     ladder.RuleID = "bot:pace"
	ruleBotAuthFail ladder.RuleID = "bot:authfail"
	ruleBotSpread   ladder.RuleID = "bot:spread"
)

// botScorePace, botScoreAuthFail and botScoreSpread are the v1 score
// contributions (log-tier evidence accumulation feeding the ban engine per
// §12; values v1-pinned, tunable when the CR wiring lands).
const (
	botScorePace     = 4 // request pacing breach
	botScoreAuthFail = 4 // auth-failure ratio breach
	botScoreSpread   = 3 // endpoint-uniqueness breach
)

// boundEventLog is the hard cap on one source's stored events (the
// bounded-state rule; expired events prune first, overflow drops oldest).
const boundEventLog = 512

// BehaviorObservation is one request's behavioral surface (§12.1: pacing,
// auth-failure ratios, endpoint uniqueness). The ingest plane knows the
// request line and the response status — it attaches one observation per
// request it wants scored, before the walk.
type BehaviorObservation struct {
	Path   string // request path as sent ("/api/items/1")
	Status int    // response status recorded on completion (0 = none)
}

const obsMetaKey = "botdef_behavior_obs_json"

// AttachBehaviorObservation stores one behavioral observation on the tx
// (same pattern as AttachHeaderView).
func AttachBehaviorObservation(tx *ingest.TxContext, o *BehaviorObservation) error {
	return attachBotJSON(tx, obsMetaKey, o)
}

// BehaviorObservationOf reads one observation back off the tx (nil = none
// attached).
func BehaviorObservationOf(tx *ingest.TxContext) *BehaviorObservation {
	o, ok := readBotJSON[BehaviorObservation](tx, obsMetaKey)
	if !ok {
		return nil
	}
	return o
}

// BehaviorWindowConfig is the §12.1 window geometry (v1-pinned; the values
// ride the policy layer the same way the merge constants do).
type BehaviorWindowConfig struct {
	PaceWindow        time.Duration    // sliding window for the pacing detector
	PaceMaxRequests   int              // pacing breaches above this many requests in-window
	AuthWindow        time.Duration    // sliding window for the auth-failure detector
	AuthMinAttempts   int              // the ratio verdict needs this many auth outcomes
	AuthFailRatio     float64          // 401/403 share that reads as an attack shape
	SpreadWindow      time.Duration    // sliding window for endpoint uniqueness
	SpreadMinRequests int              // uniqueness needs this many in-window requests
	SpreadMinDistinct int              // ... and this many distinct paths
	MaxSources        int              // hard source-count bound (bounded-state rule)
	Now               func() time.Time // injected clock (host CI suites stay wall-free)
}

// DefaultBehaviorWindowConfig pins the v1 values: pace 30 per 10 s, auth
// failures 0.75 (>= 6 attempts) per 60 s, uniqueness 12 distinct paths in
// 16 requests per 90 s, 65536 sources.
func DefaultBehaviorWindowConfig() BehaviorWindowConfig {
	return BehaviorWindowConfig{
		PaceWindow:        10 * time.Second,
		PaceMaxRequests:   30,
		AuthWindow:        60 * time.Second,
		AuthMinAttempts:   6,
		AuthFailRatio:     0.75,
		SpreadWindow:      90 * time.Second,
		SpreadMinRequests: 16,
		SpreadMinDistinct: 12,
		MaxSources:        65536,
	}
}

// BehaviorWindows holds the §12.1 behavioral family for per-source state
// (kernel counters feed userspace scoring): three sliding windows per
// source — pacing, auth-failure ratio, endpoint uniqueness — each emitting
// a DetectorVerdict on breach. A detector verdict carries the §12.1
// triple, never a bare boolean.
type BehaviorWindows struct {
	cfg   BehaviorWindowConfig
	mu    sync.Mutex
	state map[netip.Addr]*behaviorSource
}

// behaviorSource is one source's sliding-window event log (append on
// observe; expired entries prune first).
type behaviorSource struct {
	events []behaviorEvent
	last   time.Time // newest event seen (eviction ordering)
}

// behaviorEvent is one stored request observation.
type behaviorEvent struct {
	t      time.Time
	path   string
	status int
}

// authFailStatus reports whether a response status is an auth failure
// (the §12.1 credential-stuffing posture counts 401/403).
func authFailStatus(status int) bool { return status == 401 || status == 403 }

// authSuccessStatus reports whether a response status is an auth success
// outcome (2xx counts as a successful attempt; 4xx/5xx/none do not).
func authSuccessStatus(status int) bool { return status >= 200 && status < 300 }

// NewBehaviorWindows builds the windows. Zero config fields inherit the
// defaults per field (a partially-set config stays valid); a nil clock
// runs on the wall clock.
func NewBehaviorWindows(cfg BehaviorWindowConfig) *BehaviorWindows {
	def := DefaultBehaviorWindowConfig()
	if cfg.PaceWindow <= 0 {
		cfg.PaceWindow = def.PaceWindow
	}
	if cfg.PaceMaxRequests <= 0 {
		cfg.PaceMaxRequests = def.PaceMaxRequests
	}
	if cfg.AuthWindow <= 0 {
		cfg.AuthWindow = def.AuthWindow
	}
	if cfg.AuthMinAttempts <= 0 {
		cfg.AuthMinAttempts = def.AuthMinAttempts
	}
	if cfg.AuthFailRatio <= 0 {
		cfg.AuthFailRatio = def.AuthFailRatio
	}
	if cfg.SpreadWindow <= 0 {
		cfg.SpreadWindow = def.SpreadWindow
	}
	if cfg.SpreadMinRequests <= 0 {
		cfg.SpreadMinRequests = def.SpreadMinRequests
	}
	if cfg.SpreadMinDistinct <= 0 {
		cfg.SpreadMinDistinct = def.SpreadMinDistinct
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = def.MaxSources
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &BehaviorWindows{cfg: cfg, state: make(map[netip.Addr]*behaviorSource)}
}

// Observe feeds one request into the source's windows and returns the
// DetectorVerdicts that fired on this observe (§12.1 triple; empty = the
// source stays quiet). Order is pinned: pace, auth-fail, spread.
func (bw *BehaviorWindows) Observe(src netip.Addr, o BehaviorObservation) []DetectorVerdict {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	now := bw.cfg.Now()
	s := bw.state[src]
	if s == nil {
		if len(bw.state) >= bw.cfg.MaxSources {
			bw.evictOldestLocked()
		}
		s = &behaviorSource{}
		bw.state[src] = s
	}
	s.last = now
	s.events = append(s.events, behaviorEvent{t: now, path: o.Path, status: o.Status})
	bw.pruneLocked(s, now)

	var vs []DetectorVerdict
	if v, ok := bw.paceVerdict(s, now); ok {
		vs = append(vs, v)
	}
	if v, ok := bw.authVerdict(s, now); ok {
		vs = append(vs, v)
	}
	if v, ok := bw.spreadVerdict(s, now); ok {
		vs = append(vs, v)
	}
	return vs
}

// paceVerdict computes the §12.1 pacing verdict: more than
// PaceMaxRequests inside PaceWindow breaches; the excess sets the
// confidence (the cap keeps every confidence below 100 — a detector
// asserts strength, never certainty).
func (bw *BehaviorWindows) paceVerdict(s *behaviorSource, now time.Time) (DetectorVerdict, bool) {
	cut := now.Add(-bw.cfg.PaceWindow)
	n := 0
	for _, ev := range s.events {
		if !ev.t.Before(cut) {
			n++
		}
	}
	if n <= bw.cfg.PaceMaxRequests {
		return DetectorVerdict{}, false
	}
	conf := 60 + 8*(n-bw.cfg.PaceMaxRequests)
	if conf > 99 {
		conf = 99
	}
	return DetectorVerdict{
		ID:         ruleBotPace,
		Family:     FamilyBehavioral,
		Confidence: uint8(conf),
		Evidence:   fmt.Sprintf("requests=%d in %v", n, bw.cfg.PaceWindow),
	}, true
}

// authVerdict computes the §12.1 auth-failure verdict: the 401/403 share
// of auth outcomes in the window breaches at or above the ratio, once the
// in-window attempts clear the minimum (the surplus ratio sets the
// confidence; the cap keeps every confidence below 100). The v1 outcome
// pool counts 401/403 as failures and 2xx as successes without an
// endpoint registry — the per-route allowlist arrives with the CR wiring.
func (bw *BehaviorWindows) authVerdict(s *behaviorSource, now time.Time) (DetectorVerdict, bool) {
	cut := now.Add(-bw.cfg.AuthWindow)
	attempts, failures := 0, 0
	for _, ev := range s.events {
		if ev.t.Before(cut) {
			continue
		}
		if authFailStatus(ev.status) {
			attempts++
			failures++
		} else if authSuccessStatus(ev.status) {
			attempts++
		}
	}
	if attempts < bw.cfg.AuthMinAttempts {
		return DetectorVerdict{}, false
	}
	ratio := float64(failures) / float64(attempts)
	if ratio < bw.cfg.AuthFailRatio {
		return DetectorVerdict{}, false
	}
	conf := 70 + int(math.Round(100*(ratio-bw.cfg.AuthFailRatio)))
	if conf > 99 {
		conf = 99
	}
	return DetectorVerdict{
		ID:         ruleBotAuthFail,
		Family:     FamilyBehavioral,
		Confidence: uint8(conf),
		Evidence:   fmt.Sprintf("failures=%d attempts=%d ratio=%.2f", failures, attempts, ratio),
	}, true
}

// spreadVerdict computes the §12.1 endpoint-uniqueness verdict: at least
// SpreadMinRequests in-window with SpreadMinDistinct distinct paths reads
// as broad crawling (the surplus breadth sets the confidence; the cap
// keeps every confidence below 100).
func (bw *BehaviorWindows) spreadVerdict(s *behaviorSource, now time.Time) (DetectorVerdict, bool) {
	cut := now.Add(-bw.cfg.SpreadWindow)
	seen := make(map[string]struct{}, 32)
	n := 0
	for _, ev := range s.events {
		if ev.t.Before(cut) {
			continue
		}
		seen[ev.path] = struct{}{}
		n++
	}
	if n < bw.cfg.SpreadMinRequests || len(seen) < bw.cfg.SpreadMinDistinct {
		return DetectorVerdict{}, false
	}
	conf := 55 + 5*(len(seen)-bw.cfg.SpreadMinDistinct)
	if conf > 99 {
		conf = 99
	}
	return DetectorVerdict{
		ID:         ruleBotSpread,
		Family:     FamilyBehavioral,
		Confidence: uint8(conf),
		Evidence:   fmt.Sprintf("distinct=%d requests=%d", len(seen), n),
	}, true
}

// pruneLocked drops events outside the largest window and keeps the
// event log under the hard cap (bounded-state rule: expired entries
// leave first, overflow drops the oldest).
func (bw *BehaviorWindows) pruneLocked(s *behaviorSource, now time.Time) {
	maxWin := bw.cfg.PaceWindow
	if bw.cfg.AuthWindow > maxWin {
		maxWin = bw.cfg.AuthWindow
	}
	if bw.cfg.SpreadWindow > maxWin {
		maxWin = bw.cfg.SpreadWindow
	}
	cut := now.Add(-maxWin)
	keep := 0
	for _, ev := range s.events {
		if !ev.t.Before(cut) {
			s.events[keep] = ev
			keep++
		}
	}
	s.events = s.events[:keep]
	if over := len(s.events) - boundEventLog; over > 0 {
		s.events = s.events[over:]
	}
}

// evictOldestLocked frees one source slot for a new source: the
// oldest-touched entry goes, so the source map grows to the cap and
// stops there (bounded-state rule).
func (bw *BehaviorWindows) evictOldestLocked() {
	var oldest netip.Addr
	oldAt, found := time.Time{}, false
	for k, s := range bw.state {
		if !found || s.last.Before(oldAt) {
			oldest, oldAt, found = k, s.last, true
		}
	}
	delete(bw.state, oldest)
}

// LoadBehaviorVectors decodes the published behavioral test vectors from r
// (the loader takes an injected reader: the testdata file, an embedded
// feed and a CR-supplied stream all feed the same decode).
func LoadBehaviorVectors(r io.Reader) ([]BehaviorVector, error) {
	if r == nil {
		return nil, fmt.Errorf("botdef: load behavior vectors: nil reader")
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("botdef: load behavior vectors: %w", err)
	}
	var out struct {
		Vectors []BehaviorVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("botdef: load behavior vectors: %w", err)
	}
	if len(out.Vectors) == 0 {
		return nil, fmt.Errorf("botdef: load behavior vectors: no vectors")
	}
	return out.Vectors, nil
}

// BehaviorVector is one published §12.1 behavioral test vector: a scripted
// single-source request stream, and the detector ids the FINAL Observe of
// the stream must emit (the expectation pins threshold shape and decay).
type BehaviorVector struct {
	Name   string              `json:"name"`
	Source string              `json:"source"`
	Events []BehaviorEvent     `json:"events"`
	Expect BehaviorExpectation `json:"expect"`
}

// BehaviorEvent is one scripted request: OffsetMS places it on the
// vector's clock; Status is the response status recorded on completion.
type BehaviorEvent struct {
	OffsetMS int64  `json:"t_ms"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
}

// BehaviorExpectation pins the detector ids the final Observe emits
// (set-compare, order-insensitive) and the contributing family set.
type BehaviorExpectation struct {
	DetectorIDs []ladder.RuleID `json:"detector_ids"`
	Families    []Family        `json:"families"`
}

// srcAddr renders the per-source key from a flow key (v4 and v6).
func srcAddr(k ingest.FlowKey) netip.Addr {
	if k.Family == ingest.FamilyV6 {
		var a [16]byte
		copy(a[:], k.SrcIP[:])
		return netip.AddrFrom16(a)
	}
	var a [4]byte
	copy(a[:], k.SrcIP[:])
	return netip.AddrFrom4(a)
}
