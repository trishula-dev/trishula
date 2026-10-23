// rate.go carries the §13.2 rate-algorithm surface of the rate plane:
// per-route, CRD-selected limiting over composed keys. TR-20 slice, TDD
// RED state: types and plane shell exist; the algorithm bodies are
// deliberately inert (always allow, no validation) and the in-package
// table tests fail on them. The GREEN commit implements the dispatch and
// the three algorithms.
package rateban

import (
	"sync"
)

// Algorithm selects a §13.2 limiting algorithm; the names are the CRD
// field's wire vocabulary. The §13.2 score-ladder row is NOT here: it is
// the ban decision, and ScoredWindowBan v1 (§13.3, engine.go) carries it
// since TR-09 — this plane never re-implements it.
type Algorithm string

const (
	// AlgoTokenBucket: refill rate r, burst b; reject when empty (§13.2,
	// the default for API quotas).
	AlgoTokenBucket Algorithm = "tokenBucket"
	// AlgoSlidingWindow: exact count over a multi-window set (§13.2,
	// burst-sensitive endpoints; no boundary spike).
	AlgoSlidingWindow Algorithm = "slidingWindow"
	// AlgoEWMARate: exponentially weighted arrival rate per composed key
	// (§13.2, behavioral DoS signals).
	AlgoEWMARate Algorithm = "ewmaRate"
)

// KeyClass selects one key dimension from §13.2's composable key set.
// sourceIp is the default; identity keys apply when identity exists.
// A route sets several classes: each dimension evaluates against the
// route's limits at once.
type KeyClass string

const (
	KeySourceIP     KeyClass = "sourceIp"
	KeyIPRouteClass KeyClass = "ipRouteClass"
	KeyJWTSub       KeyClass = "jwtSub"
	KeyClientID     KeyClass = "clientId"
	KeyJA4Cluster   KeyClass = "ja4Cluster"
)

// WindowPolicy is one row of a multi-window policy: a count window of
// WidthSec seconds with a Limit. Widths need no nesting; any width's
// breach throttles.
type WindowPolicy struct {
	WidthSec int64
	Limit    int
}

// TokenBucketPolicy is the §13.2 token-bucket configuration: refill rate
// RatePerSec tokens per second, Burst tokens at most.
type TokenBucketPolicy struct {
	RatePerSec float64
	Burst      int
}

// EWMAPolicy is the §13.2 EWMA configuration: HalfLifeSec decay half-life
// and LimitPerSec, the maximum smoothed arrival rate in requests per
// second.
type EWMAPolicy struct {
	HalfLifeSec float64
	LimitPerSec float64
}

// RatePolicy is the per-route §13.2 selection. The operator's CRD
// compile (a later slice) fills one per route; SetRoute takes this
// value, so callers already speak the CRD's shape.
type RatePolicy struct {
	// Algorithm picks the limiting algorithm for the route.
	Algorithm Algorithm
	// KeyClasses lists the composed key dimensions; empty = sourceIp
	// (the §13.2 default).
	KeyClasses []KeyClass
	// Windows holds the multi-window set (AlgoSlidingWindow).
	Windows []WindowPolicy
	// Token holds the bucket parameters (AlgoTokenBucket).
	Token TokenBucketPolicy
	// EWMA holds the rate parameters (AlgoEWMARate).
	EWMA EWMAPolicy
}

// Arrival is one request observation; the caller fills it from the
// request view. RouteClass picks the policy; the rest feed the key
// derivation (an empty identity field skips that key — §13.2's "when
// identity exists").
type Arrival struct {
	RouteClass string
	SourceIP   string
	JWTSub     string
	ClientID   string
	JA4        string
}

// WindowCount is one window-evidence row (the §15.2 rate stage shape:
// per-window requests/limit plus breach): the count is the post-arrival
// window content, so a refused request's row can read above its limit.
type WindowCount struct {
	Key      string
	WidthSec int64
	Requests int
	Limit    int
}

// RateVerdict is the plane's decision for one arrival. §13.4 L1 maps
// !Allowed to a 429 whose Retry-After is RetryAfterSec; the field pair
// is the DX5 signature (a Retry-After always rides a throttle).
type RateVerdict struct {
	// RouteClass is the route the verdict resolved under.
	RouteClass string
	// Allowed is true when every evaluated dimension passed.
	Allowed bool
	// BreachedKeys names the composed keys over their limit, in the
	// policy's KeyClasses order.
	BreachedKeys []string
	// Windows carries the per-key, per-window counts (AlgoSlidingWindow;
	// other algorithms emit none).
	Windows []WindowCount
	// RetryAfterSec is the throttle's Retry-After in seconds (>0 exactly
	// when Allowed is false).
	RetryAfterSec int64
	// Rate is the observed ewmaRate estimate in req/s (AlgoEWMARate
	// only; 0 otherwise).
	Rate float64
}

// RatePlane evaluates the §13.2 limiting algorithms per route. The clock
// is injected (NewRatePlane) — kernel-free and telemetry-clean like the
// ban engine's construction.
type RatePlane struct {
	mu      sync.Mutex
	nowFn   func() int64 // monotonic seconds
	routes  map[string]RatePolicy
	windows map[string]*windowLog
	buckets map[string]*bucketState
	ewmas   map[string]*ewmaState
}

// NewRatePlane builds a plane on an injected monotonic-seconds clock.
func NewRatePlane(nowFn func() int64) *RatePlane {
	// TR-20 RED stub: the nil-clock guard is GREEN work (the construction
	// discipline mirrors the ban engine's New).
	return &RatePlane{
		nowFn:   nowFn,
		routes:  map[string]RatePolicy{},
		windows: map[string]*windowLog{},
		buckets: map[string]*bucketState{},
		ewmas:   map[string]*ewmaState{},
	}
}

// SetRoute installs one route's policy. GREEN work: load-time validation
// (an unknown algorithm or out-of-range parameter fails here, never
// mid-request) and a state wipe for the reloaded route.
func (p *RatePlane) SetRoute(route string, pol RatePolicy) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes[route] = pol
	return nil
}

// Arrive evaluates one arrival against its route's §13.2 policy.
// GREEN work: key derivation, the per-algorithm dispatch and the verdict.
func (p *RatePlane) Arrive(a Arrival) RateVerdict {
	p.mu.Lock()
	defer p.mu.Unlock()
	// TR-20 RED stub: inert allow.
	return RateVerdict{RouteClass: a.RouteClass, Allowed: true}
}

// Per-key state carriers. RED stubs: empty shells so the package
// compiles; GREEN fills the log and the accumulator bodies.
//
// windowLog is the sliding-window state per composed key: arrival
// seconds in (monotonic) order.
type windowLog struct{}

// bucketState is the token-bucket state per composed key.
type bucketState struct{}

// ewmaState is the smoothed-rate accumulator per composed key.
type ewmaState struct{}
