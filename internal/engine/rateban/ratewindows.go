// ratewindows.go carries the three bodies of the spec's rate algorithms behind the
// plane's dispatch: the token bucket, the exact multi-window sliding
// count and the EWMA rate accumulator. Each body takes its policy values
// and the injected clock's second as arguments — no globals, no timers.
package rateban

import "math"

// windowLog is the sliding-window state per composed key: arrival
// seconds in (monotonic) order.
type windowLog struct {
	at []int64
}

// record appends the arrival second. Every arrival records (the spec's verdict-record
// rate-stage evidence shape reads counts above a limit, so a refused
// request also counts).
func (w *windowLog) record(now int64) {
	w.at = append(w.at, now)
}

// count returns the post-arrival count for one width. The window
// boundary follows the ban algorithm's convention: an event stays valid while
// its age is at most the width.
func (w *windowLog) count(width, now int64) int {
	n := 0
	for _, t := range w.at {
		if now-t <= width {
			n++
		}
	}
	return n
}

// waitTo returns the Retry-After for one breached width: the seconds of
// silence until the count can fall under the limit. The count drops when
// the (count−limit+1)th-oldest in-window event ages out; an event leaves
// when its age passes the width, which is one second after its
// exit-tick second under the inclusive boundary. The value assumes no
// further arrivals.
func (w *windowLog) waitTo(width int64, limit int, now int64) int64 {
	var in []int64
	for _, t := range w.at {
		if now-t <= width {
			in = append(in, t)
		}
	}
	idx := len(in) - limit // the m-th-oldest index, m = count−limit+1
	if idx < 0 || idx >= len(in) {
		return 1
	}
	wait := in[idx] + width + 1 - now
	if wait < 1 {
		return 1
	}
	return wait
}

// trim drops events the widest width no longer sees (age past the
// width), so a quiet key's log shrinks to zero.
func (w *windowLog) trim(maxWidth, now int64) {
	kept := w.at[:0]
	for _, t := range w.at {
		if now-t <= maxWidth {
			kept = append(kept, t)
		}
	}
	w.at = kept
}

// bucketState is the token-bucket state per composed key: the balance
// and the refill hand. The balance is exact in the test timelines (the
// refill is r times whole seconds) and float-drifts the same way NGINX
// class refills do under fractional rates.
type bucketState struct {
	tokens  float64
	lastSec int64
}

// take checks before it spends: the rejected arrival consumes nothing
// (the spec's rate-algorithm rule: reject when empty). The wait is the ceil of the time to the
// next token at the refill rate.
func (b *bucketState) take(pol TokenBucketPolicy, now int64) (bool, int64) {
	elapsed := float64(now - b.lastSec)
	if b.tokens < float64(pol.Burst) {
		b.tokens = math.Min(float64(pol.Burst), b.tokens+elapsed*pol.RatePerSec)
	}
	b.lastSec = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := int64(math.Ceil((1 - b.tokens) / pol.RatePerSec))
	if wait < 1 {
		wait = 1
	}
	return false, wait
}

// ewmaState is the smoothed-rate accumulator per composed key (the spec's rate-algorithm
// EWMA row): a decayed arrival count. The rate estimate multiplies the
// count by ln2 over the half-life, the same decay family as the ban algorithm's
// score, and so reads in requests per second.
type ewmaState struct {
	count   float64
	lastSec int64
}

// record decays the accumulator to now, folds one arrival in and returns
// the post-arrival estimate. Steady load at rate rho settles the count
// near rho half-life over ln 2, so an operator limit is one that the
// smoothed rate reads in req/s.
func (e *ewmaState) record(halfLife float64, now int64) float64 {
	if e.count > 0 && now > e.lastSec {
		e.count *= math.Exp2(-float64(now-e.lastSec) / halfLife)
	}
	e.count++
	e.lastSec = now
	return e.count * (math.Log(2) / halfLife)
}

// countLimit is the decayed count the rate limit corresponds to:
// limit·h/ln2. A rate at or under the limit stays allowed.
func countLimit(halfLife, limit float64) float64 {
	return limit * halfLife / math.Log(2)
}

// waitToLimit returns the Retry-After for a breached EWMA key: the ceil
// of the silence that decays the count to the limit.
func (e *ewmaState) waitToLimit(halfLife, limit float64) int64 {
	c := countLimit(halfLife, limit)
	if e.count <= c {
		return 1
	}
	wait := int64(math.Ceil(halfLife * math.Log2(e.count/c)))
	if wait < 1 {
		wait = 1
	}
	return wait
}
