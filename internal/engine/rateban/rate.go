// rate.go carries the spec's rate-algorithm surface of the rate plane:
// per-route, CRD-selected limiting over composed keys. TR-20 slice. The
// The spec's score-ladder row is NOT here: it is the ban decision, and
// ScoredWindowBan v1 (the spec's ban algorithm, engine.go) carries it since TR-09 — this
// plane never re-implements it.
//
// Dispatch per route: SetRoute installs one RatePolicy (validated at
// load, never mid-request — the bundle pipeline's load discipline);
// Arrive evaluates one arrival against the route's algorithm over one
// key per selected KeyClass dimension and returns the L1-tier verdict
// fields (throttle flag, breach keys, Retry-After).
//
// Kernel-free and telemetry-clean by construction, like the ban engine:
// the clock is injected, the only observable is the returned verdict.
// The kernel rate_windows feed (the spec's kernel rate accounting) and the S6 ladder wiring are later
// slices.
package rateban

import (
	"fmt"
	"sync"
)

// Algorithm selects one limiting algorithm from the spec's rate vocabulary; the names are the CRD
// field's wire vocabulary.
type Algorithm string

const (
	// AlgoTokenBucket: refill rate r, burst b; reject when empty (the spec's rate-algorithm section,
	// the default for API quotas).
	AlgoTokenBucket Algorithm = "tokenBucket"
	// AlgoSlidingWindow: exact count over a multi-window set (the spec's rate-algorithm section,
	// burst-sensitive endpoints; no boundary spike).
	AlgoSlidingWindow Algorithm = "slidingWindow"
	// AlgoEWMARate: exponentially weighted arrival rate per composed key
	// (the spec's rate-algorithm section, behavioral DoS signals).
	AlgoEWMARate Algorithm = "ewmaRate"
)

// KeyClass selects one key dimension from the spec's composable rate-key set.
// sourceIp is the default; identity keys apply when identity exists. A
// route sets several classes: each dimension evaluates against the
// route's limits at once. State partitions per route for every class
// (the route dimension sits in the composed key), so ipRouteClass reads
// the same partition under a different name — the class exists so a CRD
// policy can name the composed pair, keeping the spec's rate vocabulary
// complete.
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

// TokenBucketPolicy is the spec's token-bucket configuration: refill rate
// RatePerSec tokens per second, Burst tokens at most.
type TokenBucketPolicy struct {
	RatePerSec float64
	Burst      int
}

// EWMAPolicy is the spec's EWMA configuration: HalfLifeSec decay half-life
// and LimitPerSec, the maximum smoothed arrival rate in requests per
// second.
type EWMAPolicy struct {
	HalfLifeSec float64
	LimitPerSec float64
}

// RatePolicy is the per-route selection from the spec's rate algorithms. The operator's CRD
// compile (a later slice) fills one per route; SetRoute takes this
// value, so callers already speak the CRD's shape.
type RatePolicy struct {
	// Algorithm picks the limiting algorithm for the route.
	Algorithm Algorithm
	// KeyClasses lists the composed key dimensions; empty = sourceIp
	// (the spec's rate-algorithm default).
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
// derivation (an empty identity field skips that key — the spec's "when
// identity exists").
type Arrival struct {
	RouteClass string
	SourceIP   string
	JWTSub     string
	ClientID   string
	JA4        string
}

// WindowCount is one window-evidence row (the spec's verdict-record rate-stage shape:
// per-window requests/limit plus breach): the count is the post-arrival
// window content, so a refused request's row can read above its limit.
type WindowCount struct {
	Key      string
	WidthSec int64
	Requests int
	Limit    int
}

// RateVerdict is the plane's decision for one arrival. The L1 enforcement tier maps
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
	// Rate is the smoothed ewmaRate estimate in req/s at the arrival
	// (AlgoEWMARate only; the largest key's estimate when several
	// evaluate; 0 otherwise).
	Rate float64
}

// RatePlane evaluates the spec's limiting algorithms per route. The clock
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
// A nil clock is a wiring error, like the ban engine's New.
func NewRatePlane(nowFn func() int64) *RatePlane {
	if nowFn == nil {
		panic("rateban: nil clock")
	}
	return &RatePlane{
		nowFn:   nowFn,
		routes:  map[string]RatePolicy{},
		windows: map[string]*windowLog{},
		buckets: map[string]*bucketState{},
		ewmas:   map[string]*ewmaState{},
	}
}

// SetRoute installs one route's policy. Validation runs at load (an
// unknown algorithm or an out-of-range parameter fails here, never
// mid-request), and a failed call leaves the previous policy and state
// untouched. A policy reload resets the route's keyed state, so a
// change starts the route on a fresh budget.
func (p *RatePlane) SetRoute(route string, pol RatePolicy) error {
	if route == "" {
		return fmt.Errorf("rateban: empty route class")
	}
	if err := validatePolicy(pol); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes[route] = pol
	p.wipeRouteLocked(route)
	return nil
}

// validatePolicy pins the CRD's parameter ranges at load. The messages
// name the defect for the operator's apply log.
func validatePolicy(pol RatePolicy) error {
	switch pol.Algorithm {
	case AlgoTokenBucket:
		if pol.Token.RatePerSec <= 0 {
			return fmt.Errorf("rateban: token bucket needs a positive refill rate")
		}
		if pol.Token.Burst < 1 {
			return fmt.Errorf("rateban: token bucket needs a burst of at least 1 token")
		}
	case AlgoSlidingWindow:
		if len(pol.Windows) < 1 {
			return fmt.Errorf("rateban: sliding window needs at least one window")
		}
		for _, w := range pol.Windows {
			if w.WidthSec < 1 {
				return fmt.Errorf("rateban: window width must be at least 1 second")
			}
			if w.Limit < 1 {
				return fmt.Errorf("rateban: window limit must be at least 1")
			}
		}
	case AlgoEWMARate:
		if pol.EWMA.HalfLifeSec <= 0 {
			return fmt.Errorf("rateban: EWMA needs a positive half-life")
		}
		if pol.EWMA.LimitPerSec <= 0 {
			return fmt.Errorf("rateban: EWMA needs a positive limit")
		}
	default:
		return fmt.Errorf("rateban: unknown algorithm %q (the §13.2 vocabulary is tokenBucket, slidingWindow, ewmaRate)", string(pol.Algorithm)) // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}
	seen := map[KeyClass]bool{}
	for _, kc := range pol.KeyClasses {
		switch kc {
		case KeySourceIP, KeyIPRouteClass, KeyJWTSub, KeyClientID, KeyJA4Cluster:
		default:
			return fmt.Errorf("rateban: unknown key class %q", string(kc))
		}
		if seen[kc] {
			return fmt.Errorf("rateban: duplicate key class %q", string(kc))
		}
		seen[kc] = true
	}
	return nil
}

// deriveKeys returns the composed keys for one arrival, in the policy's
// class order. A dimension whose value is empty falls out (the spec's rate-key rule: the
// key applies when identity exists). An empty KeyClasses list defaults
// to sourceIp, the spec's rate-key default.
func deriveKeys(classes []KeyClass, a Arrival) []string {
	if len(classes) == 0 {
		classes = []KeyClass{KeySourceIP}
	}
	keys := make([]string, 0, len(classes))
	for _, kc := range classes {
		value := keyValue(kc, a)
		if value == "" {
			continue
		}
		keys = append(keys, a.RouteClass+"/"+string(kc)+"/"+value)
	}
	return keys
}

// keyValue reads one dimension's value from the arrival.
func keyValue(kc KeyClass, a Arrival) string {
	switch kc {
	case KeySourceIP, KeyIPRouteClass:
		return a.SourceIP
	case KeyJWTSub:
		return a.JWTSub
	case KeyClientID:
		return a.ClientID
	case KeyJA4Cluster:
		return a.JA4
	}
	return ""
}

// wipeRouteLocked drops every keyed state row under one route (the
// reload contract). Callers hold p.mu.
func (p *RatePlane) wipeRouteLocked(route string) {
	for key := range p.windows {
		if hasRoutePrefix(key, route) {
			delete(p.windows, key)
		}
	}
	for key := range p.buckets {
		if hasRoutePrefix(key, route) {
			delete(p.buckets, key)
		}
	}
	for key := range p.ewmas {
		if hasRoutePrefix(key, route) {
			delete(p.ewmas, key)
		}
	}
}

// hasRoutePrefix reports whether a composed key belongs to one route
// (the route is the key's first name segment).
func hasRoutePrefix(key, route string) bool {
	return len(key) > len(route)+1 && key[:len(route)+1] == route+"/"
}

// Arrive evaluates one arrival against its route's rate policy from the spec's algorithms. Every
// arrival records in the sliding window and the EWMA accumulator —
// The spec's verdict-record rate-stage evidence carries counts above a limit, which is
// only reachable when refused requests also record. The token bucket
// checks before it spends: the rejected arrival consumes nothing. Any
// dimension's breach throttles; the Retry-After is the longest of the
// breached dimensions' waits (the spec's L1 enforcement tier plus the DX5 charter row).
func (p *RatePlane) Arrive(a Arrival) RateVerdict {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := RateVerdict{RouteClass: a.RouteClass, Windows: []WindowCount{}, BreachedKeys: []string{}}
	pol, routed := p.routes[a.RouteClass]
	if !routed {
		// Unrouted class: no rate policy from the spec's algorithms applies; allow with empty
		// evidence (the documented unrouted boundary).
		v.Allowed = true
		return v
	}
	now := p.nowFn()
	for _, key := range deriveKeys(pol.KeyClasses, a) {
		switch pol.Algorithm {
		case AlgoTokenBucket:
			st := p.buckets[key]
			if st == nil {
				st = &bucketState{tokens: float64(pol.Token.Burst), lastSec: now}
				p.buckets[key] = st
			}
			if allowed, wait := st.take(pol.Token, now); !allowed {
				v.BreachedKeys = append(v.BreachedKeys, key)
				if wait > v.RetryAfterSec {
					v.RetryAfterSec = wait
				}
			}
		case AlgoSlidingWindow:
			st := p.windows[key]
			if st == nil {
				st = &windowLog{}
				p.windows[key] = st
			}
			var maxWidth int64
			for _, wp := range pol.Windows {
				if wp.WidthSec > maxWidth {
					maxWidth = wp.WidthSec
				}
			}
			st.trim(maxWidth, now)
			st.record(now)
			for _, wp := range pol.Windows {
				c := st.count(wp.WidthSec, now)
				v.Windows = append(v.Windows, WindowCount{Key: key, WidthSec: wp.WidthSec, Requests: c, Limit: wp.Limit})
				if c > wp.Limit {
					v.BreachedKeys = append(v.BreachedKeys, key)
					if wait := st.waitTo(wp.WidthSec, wp.Limit, now); wait > v.RetryAfterSec {
						v.RetryAfterSec = wait
					}
				}
			}
		case AlgoEWMARate:
			st := p.ewmas[key]
			if st == nil {
				st = &ewmaState{}
				p.ewmas[key] = st
			}
			rate := st.record(pol.EWMA.HalfLifeSec, now)
			if rate > v.Rate {
				v.Rate = rate
			}
			if rate > pol.EWMA.LimitPerSec {
				v.BreachedKeys = append(v.BreachedKeys, key)
				if wait := st.waitToLimit(pol.EWMA.HalfLifeSec, pol.EWMA.LimitPerSec); wait > v.RetryAfterSec {
					v.RetryAfterSec = wait
				}
			}
		default:
			// SetRoute validation makes this unreachable; if it ever
			// fires, fail closed (refuse) rather than silently allow.
			v.BreachedKeys = append(v.BreachedKeys, key)
			if v.RetryAfterSec < 1 {
				v.RetryAfterSec = 1
			}
		}
	}
	v.Allowed = len(v.BreachedKeys) == 0
	return v
}
