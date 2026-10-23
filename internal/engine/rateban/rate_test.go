package rateban

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// rateArrival is one table row: an arrival script step plus the verdict
// values the row pins. A nil slice field asserts nothing, but the runner
// checks the §13.4 invariants on every row regardless: a throttle carries
// a Retry-After and names one breached key; an allow carries neither.
type rateArrival struct {
	name    string
	dt      int64 // seconds since the previous arrival
	route   string
	ip      string
	sub     string
	cid     string
	ja4     string
	ok      bool          // want Allowed
	retry   int64         // want RetryAfterSec
	rAssert bool          // assert retry
	br      []string      // want BreachedKeys (nil skips)
	win     []WindowCount // want Windows (nil skips)
	rateOn  bool          // assert the ewmaRate Rate field
	rate    float64
}

// runRateRows walks the arrival script through one plane. The plane's
// clock is the runner's integer-second hand: each row's dt advances it.
// The same clock value reaches every algorithm, so all rows in one
// scenario read one consistent timeline.
func runRateRows(t *testing.T, setup func(*RatePlane), rows []rateArrival) {
	t.Helper()
	var now int64
	p := NewRatePlane(func() int64 { return now })
	if setup != nil {
		setup(p)
	}
	for i, r := range rows {
		now += r.dt
		name := fmt.Sprintf("row %d (%s)", i+1, r.name)
		v := p.Arrive(Arrival{
			RouteClass: r.route,
			SourceIP:   r.ip,
			JWTSub:     r.sub,
			ClientID:   r.cid,
			JA4:        r.ja4,
		})
		if v.RouteClass != r.route {
			t.Errorf("%s: verdict route %q, want %q", name, v.RouteClass, r.route)
		}
		if v.Allowed != (len(v.BreachedKeys) == 0) {
			t.Errorf("%s: Allowed=%v with BreachedKeys=%v: the flag and the breach list disagree", name, v.Allowed, v.BreachedKeys)
		}
		if !v.Allowed && v.RetryAfterSec <= 0 {
			t.Errorf("%s: throttle without a Retry-After (§13.4 L1: always present)", name)
		}
		if v.Allowed && v.RetryAfterSec != 0 {
			t.Errorf("%s: allow carries a Retry-After %d", name, v.RetryAfterSec)
		}
		if v.Allowed != r.ok {
			t.Errorf("%s: Allowed=%v, want %v (RetryAfterSec=%d)", name, v.Allowed, r.ok, v.RetryAfterSec)
		}
		if r.rAssert && v.RetryAfterSec != r.retry {
			t.Errorf("%s: RetryAfterSec=%d, want %d", name, v.RetryAfterSec, r.retry)
		}
		if r.br != nil {
			if len(v.BreachedKeys) != len(r.br) {
				t.Errorf("%s: BreachedKeys=%v, want %v", name, v.BreachedKeys, r.br)
			} else {
				for j, want := range r.br {
					if v.BreachedKeys[j] != want {
						t.Errorf("%s: BreachedKeys[%d]=%q, want %q", name, j, v.BreachedKeys[j], want)
					}
				}
			}
		}
		if r.win != nil {
			if len(v.Windows) != len(r.win) {
				t.Errorf("%s: window evidence rows=%d, want %d (%v)", name, len(v.Windows), len(r.win), v.Windows)
			} else {
				for j, want := range r.win {
					got := v.Windows[j]
					if got.Key != want.Key || got.WidthSec != want.WidthSec || got.Requests != want.Requests || got.Limit != want.Limit {
						t.Errorf("%s: window row %d = %+v, want %+v", name, j, got, want)
					}
				}
			}
		}
		if r.rateOn && math.Abs(v.Rate-r.rate) > 1e-6 {
			t.Errorf("%s: Rate=%g, want %g", name, v.Rate, r.rate)
		}
	}
}

func mustSet(t *testing.T, p *RatePlane, route string, pol RatePolicy) {
	t.Helper()
	if err := p.SetRoute(route, pol); err != nil {
		t.Fatalf("SetRoute(%q): %v", route, err)
	}
}

func tokenPol(rate float64, burst int) RatePolicy {
	return RatePolicy{Algorithm: AlgoTokenBucket, Token: TokenBucketPolicy{RatePerSec: rate, Burst: burst}}
}

func slidePol(windows ...WindowPolicy) RatePolicy {
	return RatePolicy{Algorithm: AlgoSlidingWindow, Windows: windows}
}

func ewmaPol(halfLife, limit float64) RatePolicy {
	return RatePolicy{Algorithm: AlgoEWMARate, EWMA: EWMAPolicy{HalfLifeSec: halfLife, LimitPerSec: limit}}
}

// TestTokenBucketRows pins the §13.2 token-bucket row: refill rate r,
// burst b, reject when empty. The rejected arrival consumes nothing, and
// its Retry-After is the wait for the next token (§13.4 L1/DX5: always
// present on a throttle).
func TestTokenBucketRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  RatePolicy
		rows []rateArrival
	}{
		{
			name: "burst drains, then the bucket rejects when empty",
			pol:  tokenPol(1, 2),
			rows: []rateArrival{
				{name: "first burst token", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "second burst token", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "empty bucket rejects", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 1, br: []string{"auth/sourceIp/1.2.3.4"}},
				{name: "refill gives one token after one second", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "empty again rejects", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 1},
				{name: "one more refill", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
			},
		},
		{
			name: "refill never exceeds the burst cap",
			pol:  tokenPol(1, 3),
			rows: []rateArrival{
				{name: "burst drain 1", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "burst drain 2", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "burst drain 3", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "empty bucket rejects", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 1},
				{name: "idle 30s refills to the cap, not 30 tokens", dt: 30, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "cap second token", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "cap third token", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "empty again rejects", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 1},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runRateRows(t, func(p *RatePlane) { mustSet(t, p, "auth", tc.pol) }, tc.rows)
		})
	}
}

// TestSlidingWindowRows pins the §13.2 sliding-window row: exact count
// over the window, no boundary spike. The count records every arrival,
// refused ones included — that is the only reading under which the §15.2
// rate-stage evidence (requests over limit, breach: true) is reachable.
// Breach = post-arrival count > limit. A refused arrival's Retry-After
// is the wait until the count can fall below the limit (no further
// arrivals assumed).
func TestSlidingWindowRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  RatePolicy
		rows []rateArrival
	}{
		{
			name: "exact count breaches at the limit",
			pol:  slidePol(WindowPolicy{WidthSec: 10, Limit: 3}),
			rows: []rateArrival{
				{name: "count 1", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "count 2", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "count 3 stays under", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "4th breaches", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 11,
					br:  []string{"auth/sourceIp/1.2.3.4"},
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 4, Limit: 3}}},
			},
		},
		{
			name: "events age out and the window reopens",
			pol:  slidePol(WindowPolicy{WidthSec: 10, Limit: 3}),
			rows: []rateArrival{
				{name: "fill", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "fill", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "fill", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "after one width every event is out", dt: 11, route: "auth", ip: "1.2.3.4", ok: true,
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 1, Limit: 3}}},
			},
		},
		{
			name: "multi-window set: any window breaches",
			pol:  slidePol(WindowPolicy{WidthSec: 5, Limit: 4}, WindowPolicy{WidthSec: 60, Limit: 5}),
			rows: []rateArrival{
				{name: "t=0", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "t=3", dt: 3, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "t=5", dt: 2, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "t=7", dt: 2, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "t=9", dt: 2, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "t=11 only the wide window breaches", dt: 2, route: "auth", ip: "1.2.3.4", rAssert: true, retry: 53,
					br: []string{"auth/sourceIp/1.2.3.4"},
					win: []WindowCount{
						{Key: "auth/sourceIp/1.2.3.4", WidthSec: 5, Requests: 3, Limit: 4},
						{Key: "auth/sourceIp/1.2.3.4", WidthSec: 60, Requests: 6, Limit: 5},
					}},
			},
		},
		{
			name: "no boundary spike at a window edge",
			pol:  slidePol(WindowPolicy{WidthSec: 10, Limit: 5}),
			rows: []rateArrival{
				{name: "five at t=9 (a fixed bucket would reset next tick)", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "still inside", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "still inside", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "still inside", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "fifth at t=9 stays under", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "t=10: the same window holds all six", dt: 1, route: "auth", ip: "1.2.3.4", rAssert: true, retry: 10,
					br: []string{"auth/sourceIp/1.2.3.4"}},
			},
		},
		{
			name: "a refused arrival still records the count",
			pol:  slidePol(WindowPolicy{WidthSec: 10, Limit: 1}),
			rows: []rateArrival{
				{name: "first passes", route: "auth", ip: "1.2.3.4", ok: true},
				{name: "second refuses, count 2", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 11,
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 2, Limit: 1}}},
				{name: "third refuses, count 3", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 11,
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 3, Limit: 1}}},
				{name: "fourth at t=1 refuses from the older log", dt: 1, route: "auth", ip: "1.2.3.4", rAssert: true, retry: 11,
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 4, Limit: 1}}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runRateRows(t, func(p *RatePlane) { mustSet(t, p, "auth", tc.pol) }, tc.rows)
		})
	}
}

// burstArrivals builds n same-second same-key burst rows: arrivals 1..n
// at dt 0 (the runner's per-row arrival is one request, so a burst of 20
// needs 20 rows).
func burstArrivals(n int) []rateArrival {
	rows := make([]rateArrival, 0, n)
	for i := 1; i <= n; i++ {
		rows = append(rows, rateArrival{name: fmt.Sprintf("arrival %d", i), route: "auth", ip: "1.2.3.4", ok: true})
	}
	return rows
}

// ewmaBurstRows is the 20-arrival instant burst at t=0: rows 1..14 stay
// under the limit-1 smoothed rate, rows 15..20 refuse. The refusal
// rows' Retry-After comes from the half-life decay: h·log2(C/Ctarget)
// with Ctarget = limit·h/ln2.
func ewmaBurstRows() []rateArrival {
	rows := burstArrivals(14)
	return append(rows,
		rateArrival{name: "15 breaches the smoothed rate", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 1, br: []string{"auth/sourceIp/1.2.3.4"}, rateOn: true, rate: 1.039721},
		rateArrival{name: "16", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 2},
		rateArrival{name: "17", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 3},
		rateArrival{name: "18", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 4},
		rateArrival{name: "19", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 4},
		rateArrival{name: "20 refuses with the longest retry", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 5, br: []string{"auth/sourceIp/1.2.3.4"}, rateOn: true, rate: 1.386294},
	)
}

// TestEWMARateRows pins the §13.2 EWMA-rate row: an exponentially weighted
// arrival rate per composed key, at the same decay family as §13.3's
// score. R = (ln2/h)·Σ 2^(−age/h) reads in req/s. The arrival records,
// the post-arrival rate evaluates, and breach = R > limit.
func TestEWMARateRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  RatePolicy
		rows []rateArrival
	}{
		{
			name: "instant burst crosses the limit",
			pol:  ewmaPol(10, 1),
			rows: ewmaBurstRows(),
		},
		{
			name: "half-life decay releases the key",
			pol:  ewmaPol(10, 1),
			rows: append(ewmaBurstRows(),
				rateArrival{name: "one half-life of silence later the key reopens", dt: 15, route: "auth", ip: "1.2.3.4", ok: true, rateOn: true, rate: 0.559444}),
		},
		{
			name: "steady sub-limit rate never breaches",
			pol:  ewmaPol(10, 1),
			rows: []rateArrival{
				{name: "1/s 1", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 2", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 3", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 4", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 5", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 6", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 7", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 8", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 9", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 10", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 11", dt: 1, route: "auth", ip: "1.2.3.4", ok: true},
				{name: "1/s 12 rate tops at 0.585/s", dt: 1, route: "auth", ip: "1.2.3.4", ok: true, rateOn: true, rate: 0.584523},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runRateRows(t, func(p *RatePlane) { mustSet(t, p, "auth", tc.pol) }, tc.rows)
		})
	}
}

// TestKeyCompositionRows pins §13.2's key contract: sourceIp is the
// default; a route may limit per-IP and per-identity simultaneously; an
// identity that does not exist skips its key.
func TestKeyCompositionRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  RatePolicy
		rows []rateArrival
	}{
		{
			name: "empty KeyClasses defaults to sourceIp",
			pol:  slidePol(WindowPolicy{WidthSec: 10, Limit: 3}),
			rows: []rateArrival{
				{name: "derived sourceIp key carries the evidence", route: "auth", ip: "1.2.3.4", ok: true,
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 1, Limit: 3}}},
			},
		},
		{
			name: "per-IP and per-identity evaluate simultaneously",
			pol: func() RatePolicy {
				p := slidePol(WindowPolicy{WidthSec: 10, Limit: 1})
				p.KeyClasses = []KeyClass{KeySourceIP, KeyJWTSub}
				return p
			}(),
			rows: []rateArrival{
				{name: "ip and identity both fresh", route: "auth", ip: "1.2.3.4", sub: "user-1", ok: true,
					win: []WindowCount{
						{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 1, Limit: 1},
						{Key: "auth/jwtSub/user-1", WidthSec: 10, Requests: 1, Limit: 1}}},
				{name: "next identity keeps the IP over its limit", route: "auth", ip: "1.2.3.4", sub: "user-2", rAssert: true, retry: 11,
					br: []string{"auth/sourceIp/1.2.3.4"},
					win: []WindowCount{
						{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 2, Limit: 1},
						{Key: "auth/jwtSub/user-2", WidthSec: 10, Requests: 1, Limit: 1}}},
				{name: "the same identity as row 1 breaches both dimensions", route: "auth", ip: "1.2.3.4", sub: "user-1", rAssert: true, retry: 11,
					br: []string{"auth/sourceIp/1.2.3.4", "auth/jwtSub/user-1"},
					win: []WindowCount{
						{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 3, Limit: 1},
						{Key: "auth/jwtSub/user-1", WidthSec: 10, Requests: 2, Limit: 1}}},
			},
		},
		{
			name: "a missing identity skips its key",
			pol: func() RatePolicy {
				p := slidePol(WindowPolicy{WidthSec: 10, Limit: 3})
				p.KeyClasses = []KeyClass{KeySourceIP, KeyJWTSub}
				return p
			}(),
			rows: []rateArrival{
				{name: "only the IP key evaluates", route: "auth", ip: "1.2.3.4", ok: true,
					win: []WindowCount{{Key: "auth/sourceIp/1.2.3.4", WidthSec: 10, Requests: 1, Limit: 3}}},
			},
		},
		{
			name: "ja4Cluster and clientId keys derive their values",
			pol: func() RatePolicy {
				p := slidePol(WindowPolicy{WidthSec: 10, Limit: 3})
				p.KeyClasses = []KeyClass{KeyJA4Cluster, KeyClientID}
				return p
			}(),
			rows: []rateArrival{
				{name: "both keys carry the evidence", route: "auth", ip: "1.2.3.4", cid: "client-9", ja4: "g123", ok: true,
					win: []WindowCount{
						{Key: "auth/ja4Cluster/g123", WidthSec: 10, Requests: 1, Limit: 3},
						{Key: "auth/clientId/client-9", WidthSec: 10, Requests: 1, Limit: 3}}},
				{name: "the ja4 key fills from its own dimension", route: "auth", ip: "1.2.3.4", cid: "client-9", ja4: "g123", ok: true},
			},
		},
		{
			name: "ipRouteClass names the route in its key",
			pol: func() RatePolicy {
				p := slidePol(WindowPolicy{WidthSec: 10, Limit: 3})
				p.KeyClasses = []KeyClass{KeyIPRouteClass}
				return p
			}(),
			rows: []rateArrival{
				{name: "route joins the key", route: "auth", ip: "1.2.3.4", ok: true,
					win: []WindowCount{{Key: "auth/ipRouteClass/1.2.3.4", WidthSec: 10, Requests: 1, Limit: 3}}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runRateRows(t, func(p *RatePlane) { mustSet(t, p, "auth", tc.pol) }, tc.rows)
		})
	}
}

// TestRatePlaneSelectsPerRoute pins the CRD-selected dispatch: the route
// name picks the policy, so the same cadence throttles on one route and
// passes on another; an unrouted class allows.
func TestRatePlaneSelectsPerRoute(t *testing.T) {
	t.Run("two routes run two algorithms independently", func(t *testing.T) {
		runRateRows(t, func(p *RatePlane) {
			mustSet(t, p, "auth", slidePol(WindowPolicy{WidthSec: 10, Limit: 1}))
			mustSet(t, p, "api", tokenPol(1, 1))
		}, []rateArrival{
			{name: "auth passes", route: "auth", ip: "1.2.3.4", ok: true},
			{name: "auth throttles on its window", route: "auth", ip: "1.2.3.4", rAssert: true, retry: 11,
				br: []string{"auth/sourceIp/1.2.3.4"}},
			{name: "api runs its own token bucket", route: "api", ip: "1.2.3.4", ok: true},
			{name: "api's bucket also drains per route", route: "api", ip: "1.2.3.4", rAssert: true, retry: 1,
				br: []string{"api/sourceIp/1.2.3.4"}},
		})
	})
	t.Run("unrouted class allows with no window rows", func(t *testing.T) {
		runRateRows(t, func(p *RatePlane) {
			mustSet(t, p, "auth", slidePol(WindowPolicy{WidthSec: 10, Limit: 1}))
		}, []rateArrival{
			{name: "no policy for the route", route: "none", ip: "1.2.3.4", ok: true, win: []WindowCount{}},
		})
	})
}

// TestRatePlaneReloadResetsState pins the reload contract: SetRoute with a
// new (or identical) policy wipes the route's keyed state, so a reload
// starts every route from a fresh budget. The contract spans arrivals AND
// a SetRoute call, which a row cannot express.
func TestRatePlaneReloadResetsState(t *testing.T) {
	pol := slidePol(WindowPolicy{WidthSec: 10, Limit: 2})
	var now int64
	p := NewRatePlane(func() int64 { return now })
	mustSet(t, p, "auth", pol)
	arr := func() {
		if v := p.Arrive(Arrival{RouteClass: "auth", SourceIP: "1.2.3.4"}); !v.Allowed {
			t.Fatalf("Arrive before reload: Allowed=false, want true (RetryAfterSec=%d)", v.RetryAfterSec)
		}
	}
	arr()
	arr()
	if v := p.Arrive(Arrival{RouteClass: "auth", SourceIP: "1.2.3.4"}); v.Allowed {
		t.Fatal("Arrive at limit: Allowed=true, want throttle")
	}
	if err := p.SetRoute("auth", pol); err != nil {
		t.Fatalf("SetRoute reload: %v", err)
	}
	arr()
}

// TestRatePlaneLoadTimeValidation pins the load-time discipline: an
// invalid policy fails SetRoute with an error naming the defect, and a
// failed SetRoute leaves the route unrouted (never half-applied).
func TestRatePlaneLoadTimeValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  RatePolicy
		want string
	}{
		{name: "unknown algorithm", pol: RatePolicy{Algorithm: "bogus"}, want: "bogus"},
		{name: "sliding with no windows", pol: RatePolicy{Algorithm: AlgoSlidingWindow}, want: "window"},
		{name: "sliding width below one second", pol: slidePol(WindowPolicy{WidthSec: 0, Limit: 1}), want: "width"},
		{name: "sliding limit below one", pol: slidePol(WindowPolicy{WidthSec: 10, Limit: 0}), want: "limit"},
		{name: "token refill rate at zero", pol: tokenPol(0, 2), want: "refill rate"},
		{name: "token burst below one", pol: tokenPol(1, 0), want: "burst"},
		{name: "ewma half-life at zero", pol: ewmaPol(0, 1), want: "half-life"},
		{name: "ewma limit at zero", pol: ewmaPol(10, 0), want: "limit"},
		{name: "duplicate key classes", pol: func() RatePolicy {
			p := slidePol(WindowPolicy{WidthSec: 10, Limit: 1})
			p.KeyClasses = []KeyClass{KeySourceIP, KeySourceIP}
			return p
		}(), want: "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now int64
			p := NewRatePlane(func() int64 { return now })
			err := p.SetRoute("auth", tc.pol)
			if err == nil {
				t.Fatal("SetRoute accepted an invalid policy, want a load-time error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err.Error(), tc.want)
			}
			if v := p.Arrive(Arrival{RouteClass: "auth", SourceIP: "1.2.3.4"}); !v.Allowed {
				t.Error("a failed SetRoute left the route governed: want unrouted (never half-applied)")
			}
		})
	}
}

// TestRatePlaneRejectsNilClock pins the construction discipline: a nil
// clock is a wiring error at build time, like the ban engine's.
func TestRatePlaneRejectsNilClock(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil clock: NewRatePlane returned, want a construction panic")
		}
	}()
	NewRatePlane(nil)
}
