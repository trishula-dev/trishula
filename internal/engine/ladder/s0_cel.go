package ladder

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// viewMetaKey is the tx-Metadata slot carrying the parsed §11.3 view (the
// HTTP/1 parse product, JSON-encoded). The typed engine plumbing lands
// with the parity walk; the key is the attachment contract until then.
const viewMetaKey = "request_view_json"

// AttachView stores a parsed §11.3 request on the tx (engine plumbing +
// tests; JSON keeps ingest decoupled from cel).
func AttachView(tx *ingest.TxContext, r *cel.Request) error {
	if tx == nil || r == nil {
		return fmt.Errorf("attach view: nil tx or request")
	}
	if tx.Metadata == nil {
		tx.Metadata = map[string]string{}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("attach view: %w", err)
	}
	tx.Metadata[viewMetaKey] = string(b)
	return nil
}

// txView reads the attached §11.3 view back (nil = none attached).
func txView(tx *ingest.TxContext) *cel.Request {
	if tx == nil {
		return nil
	}
	raw, ok := tx.Metadata[viewMetaKey]
	if !ok || raw == "" {
		return nil
	}
	var r cel.Request
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil
	}
	return &r
}

// KernelHits is the TR-05c S0 stage: consult the shield verdict/ban state
// for the tx's source and return a decisive fragment on a live ban.
//
// The dependency is INVERTED from the PRD sketch: the engine never touches
// *ebpf.Map itself — kernelHitChecker is the (linux-only) loader-API
// adapter (shieldMapsChecker); host CI runs the pure in-memory checker.
// Check is safe for concurrent use when the delegate is.
type KernelHits struct {
	kernelHitChecker func(src netip.Addr, nowNS uint64) (khit, error)
}

// khit is one kernel-state probe result (mirror of the wire outcome).
type khit struct {
	banned     bool
	untilTS    uint64
	tier       uint8
	reasonCode uint16
}

// NewKernelHits wires the stage onto a checker (real loader-API adapter on
// the engine host; in-memory state in tests).
func NewKernelHits(kernelHitChecker func(src netip.Addr, nowNS uint64) (khit, error)) *KernelHits {
	return &KernelHits{kernelHitChecker: kernelHitChecker}
}

// Stage pins S0 (ladder position 0: the µs cache consult — §19.1).
func (k *KernelHits) Stage() Stage { return StageKernel }

// Evaluate probes kernel state once per tx. The tx's source address
// decides the key; a tx without a parseable source yields NO fragment
// (S0 cannot invent a key — and a fabricated "clean" would fail open,
// the direction this stage must never take).
func (k *KernelHits) Evaluate(tx *ingest.TxContext) *Verdict {
	src, ok := txSourceIP(tx)
	if !ok {
		return nil
	}
	h, err := k.kernelHitChecker(src, clockOrZero(tx))
	if err != nil {
		// Probe failure: no fragment, never a fabricated verdict — the
		// walk continues and downstream stages own the tx (S0 is an
		// acceleration, not the only wall).
		return nil
	}
	if !h.banned {
		return nil
	}
	return &Verdict{
		Action: ActionBan,
		Rules:  []RuleID{kernelBanRuleID(h)},
		Score:  int64(h.tier), // kernel tier seeds the ban engine's score input
		Phase:  PhaseRequestHeaders,
	}
}

// kernelBanRuleID renders the rule id for a kernel ban hit (traceable to
// the shield's reason code + tier: shield:ban:t<tier>:r<code>).
func kernelBanRuleID(h khit) RuleID {
	return RuleID(fmt.Sprintf("shield:ban:t%d:r%d", h.tier, h.reasonCode))
}

// txSourceIP extracts the tx source address (dual-stack, family-
// discriminated per defect #62).
func txSourceIP(tx *ingest.TxContext) (netip.Addr, bool) {
	if tx == nil {
		return netip.Addr{}, false
	}
	switch tx.Key.Family {
	case ingest.FamilyV4:
		return netip.AddrFrom4(tx.Key.SrcIP), true
	case ingest.FamilyV6:
		return netip.AddrFrom16(tx.Key.SrcIP6), true
	}
	return netip.Addr{}, false
}

// clockOrZero uses the tx's last-seen monotonic timestamp as the probe
// clock (the loader shares CLOCK_MONOTONIC with the kernel — bans are
// written in loader-clock nanoseconds, Expired's `now >= until` parity).
func clockOrZero(tx *ingest.TxContext) uint64 {
	if tx == nil {
		return 0
	}
	return tx.LastNS
}

// CELEval is the TR-05c S3 slot (the TR-02 seed pack evaluation). v0 runs
// over the REQUEST parsed into the view (AttachView). Verdicts are
// LOG-ONLY at this slice: an enforce-declared rule action never becomes
// block/ban — issue #5 posture, pinned by TestCELEvalMatchLogsPinsLogOnly.
type CELEval struct {
	mu   sync.RWMutex
	pack *cel.RulePack
}

// NewCELEval wires the S3 slot onto a loaded rule pack.
func NewCELEval(pack *cel.RulePack) *CELEval { return &CELEval{pack: pack} }

// SetPack hot-swaps the evaluated pack (controller apply lands here in
// TR-17; nil/empty is a wiring error — an empty-walk S3 is the silent-skip
// shape Use() exists to prevent).
func (c *CELEval) SetPack(p *cel.RulePack) error {
	if p == nil || len(p.Rules) == 0 {
		return fmt.Errorf("cel eval: empty rule pack (wiring error, not an empty opinion)")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pack = p
	return nil
}

// Stage pins S3.
func (c *CELEval) Stage() Stage { return StageCEL }

// Evaluate runs every rule over the tx's view, folding rule verdicts into
// one fragment: match=false rules contribute nothing; match=true rules
// become a LOG action (regardless of declared action — log-only slice)
// with the rule ids in pack order; error verdicts record the rule id as
// <id>:error and keep walking (fail-safe: an uncompilable/over-budget rule
// is evidence, never a match and never a silent skip).
func (c *CELEval) Evaluate(tx *ingest.TxContext) *Verdict {
	view := txView(tx)
	if view == nil {
		return nil // no parsed request on the tx: no opinion (parse stages own it)
	}
	c.mu.RLock()
	pack := c.pack
	c.mu.RUnlock()
	if pack == nil {
		return nil
	}
	var (
		rules []RuleID
		score int64
	)
	for i := range pack.Rules {
		r := &pack.Rules[i]
		v, err := r.Eval(*view)
		if err != nil {
			// Error verdicts are recorded evidence, never matches (#5
			// log-only slice; TR-09 scores them later).
			rules = append(rules, RuleID(r.ID+":error"))
			continue
		}
		if v.Match {
			rules = append(rules, RuleID(r.ID))
			score++
		}
	}
	if len(rules) == 0 {
		return nil
	}
	return &Verdict{
		Action: ActionLog, // LOG-ONLY slice: declared actions stay log (pinned by test)
		Rules:  rules,
		Score:  score,
		Phase:  PhaseRequestHeaders,
	}
}

// shieldAdapterState is the in-memory kernel-state stand-in (tests + the
// pure-CI path: the same query shape the loader adapter answers).
type shieldAdapterState struct {
	bans map[string]khit // netip.Addr string form (canonical keyed compare)
	mu   sync.RWMutex
}

func newShieldAdapterState() *shieldAdapterState {
	return &shieldAdapterState{bans: map[string]khit{}}
}

func banStateKey(ip netip.Addr) string { return ip.Unmap().String() }

func (s *shieldAdapterState) setBan(ip netip.Addr, untilTS uint64, tier uint8, reason uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans[banStateKey(ip)] = khit{banned: true, untilTS: untilTS, tier: tier, reasonCode: reason}
}

func (s *shieldAdapterState) clearBan(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bans, banStateKey(ip))
}

// checker conforms to the KernelHits delegate signature.
func (s *shieldAdapterState) checker(src netip.Addr, nowNS uint64) (khit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.bans[banStateKey(src)]
	if !ok {
		return khit{}, nil
	}
	if nowNS >= h.untilTS {
		return khit{}, nil // expired bans are clean misses (loader parity: now >= until)
	}
	return h, nil
}

// shieldMapsChecker adapts the REAL loader surface (shield maps' lookup +
// expiry) to the stage delegate — the engine-host (linux) wiring; this
// function builds everywhere, the maps come from the linux loader.
func shieldMapsChecker(lookup func(netip.Addr) (untilTS uint64, tier uint8, reason uint16, ok bool, err error)) func(netip.Addr, uint64) (khit, error) {
	return func(src netip.Addr, nowNS uint64) (khit, error) {
		until, tier, reason, ok, err := lookup(src)
		if err != nil {
			return khit{}, err
		}
		if !ok || nowNS >= until {
			return khit{}, nil
		}
		return khit{banned: true, untilTS: until, tier: tier, reasonCode: reason}, nil
	}
}
