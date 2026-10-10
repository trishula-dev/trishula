package shield

// TR-10 (issue #10) adapter: BanEnforcer closes the enforcement loop. A
// rateban would-ban (the engine's Assess() record) is converted to a
// kernel bans_v4 write at the kernel clock (publish) and echoed to the
// evidence stream (§13.5: verdict "ban" once the kernel state exists;
// publish failures are failures of the ban, evidenced). Reconcile
// auto-lifts expired bans (now_ms >= until_ms — engine expiry parity).
import (
	"fmt"
	"net/netip"
	"sync"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// MapPublisher is the bans_v4 write surface (kernel maps in the loader
// path, a stub in tests).
type MapPublisher interface {
	PutBansV4(k BansV4Key, v BansV4Val) error
	DeleteBansV4(k BansV4Key) error
}

// BanEnforcer converts engine would-bans to kernel state + records.
type BanEnforcer struct {
	pub     MapPublisher
	sink    *JSONLEvidenceSink
	clockNs func() (uint64, error) // the kernel clock seam (Loader.NowNS in prod)

	mu  sync.Mutex
	liv map[[4]byte]uint64 // published bans: saddr → ban_until_ms
}

// NewBanEnforcer builds an enforcer over a bans_v4 publisher + evidence
// sink. pub may be nil (evidence-only mode: no kernel write); sink must
// be non-nil.
func NewBanEnforcer(pub MapPublisher, sink *JSONLEvidenceSink) *BanEnforcer {
	if sink == nil {
		panic("shield: nil evidence sink")
	}
	return &BanEnforcer{pub: pub, sink: sink}
}

// SetClock wires the kernel-clock seam (the loader's NowNS after Attach;
// tests inject a fixed reading).
func (b *BanEnforcer) SetClock(fn func() (uint64, error)) {
	b.mu.Lock()
	b.clockNs = fn
	b.mu.Unlock()
}

// Record converts and publishes one engine would-ban: the ban window
// (BantimeSec — the engine's applied duration, the remainder at crossing)
// is rebased onto the kernel clock at publish time, the score travels as
// score × 100 (u16 wire) and the §13.4 tier chooses the wire reason code.
// Verdict "ban" is written ONLY when the kernel state landed (or no
// publisher is wired: evidence-only mode); a failed publish is a failed
// ban — evidenced with publish_err, verdict left at the engine's value.
func (b *BanEnforcer) Record(rec rateban.BanEvidence) error {
	nowNs, err := b.readClock()
	if err != nil {
		return fmt.Errorf("shield: ban %s: %w", rec.Key, err)
	}
	nowMs := nowNs / 1_000_000
	w := BanRecord{
		Key:         rec.Key,
		Mode:        rec.Mode,
		Verdict:     rec.Verdict,
		Tier:        rec.Tier,
		Score:       rec.Score,
		Threshold:   rec.Threshold,
		Events:      rec.Events,
		ReasonCodes: rec.ReasonCodes,
		AtSec:       rec.AtSec,
		UntilSec:    rec.UntilSec,
		Recidivism:  rec.Recidivism,
		BantimeSec:  rec.BantimeSec,
		Note:        rec.Note,
	}

	ip, perr := netip.ParseAddr(rec.Key)
	if perr != nil || !ip.Unmap().Is4() {
		w.PublishErr = fmt.Sprintf("key %q is not an IPv4 literal", rec.Key)
		rerr := b.sink.Record(w)
		return joinErr(
			fmt.Errorf("shield: ban %s: publish: not an IPv4 literal", rec.Key), rerr)
	}
	src := ip.Unmap()
	w.SourceIP = src.String()

	code, cerr := ReasonCode(rec.Tier)
	if cerr != nil {
		w.PublishErr = cerr.Error()
		rerr := b.sink.Record(w)
		return joinErr(fmt.Errorf("shield: ban %s: publish: %w", rec.Key, cerr), rerr)
	}
	w.ReasonCode = code
	untilMs := nowMs + uint64(rec.BantimeSec)*1000
	w.UntilMS = untilMs
	w.ScoreCenti = scoreCenti(rec.Score)

	if b.pub != nil {
		k, kerr := BansV4KeyFromIP(src)
		if kerr != nil {
			w.PublishErr = kerr.Error()
			rerr := b.sink.Record(w)
			return joinErr(fmt.Errorf("shield: ban %s: publish: %w", rec.Key, kerr), rerr)
		}
		v := BansV4Val{BanUntilMs: untilMs, Score: w.ScoreCenti, ReasonCode: code}
		if perr := b.pub.PutBansV4(k, v); perr != nil {
			w.PublishErr = perr.Error()
			rerr := b.sink.Record(w)
			return joinErr(fmt.Errorf("shield: ban %s: publish: %w", rec.Key, perr), rerr)
		}
		b.mu.Lock()
		if b.liv == nil {
			b.liv = map[[4]byte]uint64{}
		}
		b.liv[k.SAddr] = untilMs
		b.mu.Unlock()
		w.Published = true
		w.Verdict = "ban"
	}
	return b.sink.Record(w)
}

// Reconcile lifts expired bans: every published ban whose until_ms is at
// or before nowMs is deleted from the kernel table and dropped from the
// live set (auto-lift; the engine's upkeep parity — now >= until means
// the ban is over). Returns the count lifted.
func (b *BanEnforcer) Reconcile(nowMs int64) int {
	b.mu.Lock()
	var expired [][4]byte
	for sa, until := range b.liv {
		if nowMs >= int64(until) {
			expired = append(expired, sa)
		}
	}
	pub := b.pub
	b.mu.Unlock()
	lifted := 0
	for _, sa := range expired {
		if pub != nil {
			if err := pub.DeleteBansV4(BansV4Key{SAddr: sa, Family: FamilyV4, KeyClass: KeyClassIP}); err != nil {
				continue // stays live; retried on the next reconcile
			}
		}
		b.mu.Lock()
		delete(b.liv, sa)
		b.mu.Unlock()
		lifted++
	}
	return lifted
}

// Sink exposes the enforcer's evidence stream (the loader/tests read the
// records; OTLP/log wiring consumes the slice).
func (b *BanEnforcer) Sink() *JSONLEvidenceSink { return b.sink }

func (b *BanEnforcer) readClock() (uint64, error) {
	b.mu.Lock()
	clk := b.clockNs
	b.mu.Unlock()
	if clk == nil {
		return 0, fmt.Errorf("shield: no kernel clock wired (loader's NowNS)")
	}
	return clk()
}

// scoreCenti encodes the §13.3 score as score × 100 with round-half-up
// (saturating at the u16 max) — the wire's 2-decimal score.
func scoreCenti(s float64) uint16 {
	c := uint64(s*100 + 0.5)
	if c > 65535 {
		c = 65535
	}
	return uint16(c)
}

func joinErr(a, b error) error {
	if b == nil {
		return a
	}
	return fmt.Errorf("%v; evidence: %w", a, b)
}
