package botdef

import (
	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Detector is the §12 bot detector: a ladder Evaluator at the fixed S5
// StageBots slot. v0 emits ONLY log-tier fragments (PRD §12: single-detector
// matches log and score — consensus/blocking arrives with TR-19's merge
// policy). Detached transactions (no attached ClientHelloSummary and/or
// HeaderView — the state of every tx until TR-15/29 wire the extraction)
// produce NO fragment; the S5 stage stays silent rather than fabricate a
// verdict. No-op when the engine is unwired (ladder skips empty slots).
type Detector struct{}

// NewDetector builds the bot detector (stateless v0).
func NewDetector() *Detector { return &Detector{} }

// Stage pins the fixed §19.1 ladder position: S5 bots.
func (d *Detector) Stage() ladder.Stage { return ladder.StageBots }

// Evaluate walks the two v0 detectors over the attached evidence and folds
// the §12 evidence into one S5 fragment (always log-tier at v0). Wire
// contract:
//
//   - JA4 evidence: the computed fingerprint carries the bot-vs-browser
//     prior, not a verdict by itself (§12.3 honest limits — a hash without
//     the tooling DB is a prior); the a-section encodes the tool-vs-browser
//     ALPN/count shape.
//   - Header evidence: the header-plane classification (browser-ish vs
//     tool-ish) is a direct per-request signal.
//   - Both planes agreeing on "tool" is the strongest v0 evidence: the curl
//     verdict. Evidence and score always accumulate; the Action stays log.
//
// GREEN fills the fragment assembly; RED stub fails.
func (d *Detector) Evaluate(tx *ingest.TxContext) *ladder.Verdict { return nil }

// AttachClientHello stores one terminated-hop ClientHello summary on the tx
// for the S5 stage to find (JSON keeps ingest decoupled from botdef, same
// pattern as ladder.AttachView). The kernel/ingest child (TR-29) calls this
// once its extraction lands.
func AttachClientHello(tx *ingest.TxContext, ch *ClientHelloSummary) error { return nil } // GREEN

// ClientHelloOf reads a summary back off the tx (nil = none attached).
func ClientHelloOf(tx *ingest.TxContext) *ClientHelloSummary { return nil } // GREEN

// AttachHeaderView stores one ordered header view on the tx (same pattern;
// the header fingerprint consumes it).
func AttachHeaderView(tx *ingest.TxContext, hv *HeaderView) error { return nil } // GREEN

// HeaderViewOf reads a header view back off the tx (nil = none attached).
func HeaderViewOf(tx *ingest.TxContext) *HeaderView { return nil } // GREEN

// LabLogLine renders one §12 lab-log verdict line (the acceptance surface:
// a curl-vs-browser pair produces two of these with distinct ja4= and hf=
// values). GREEN fills the renderer; RED stub fails.
func LabLogLine(tx *ingest.TxContext) string { return "" } // GREEN
