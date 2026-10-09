// Package ladder implements the §2.3/§19.1 detection ladder: fixed S0–S7
// stage positions over a transaction context, short-circuiting on the first
// decisive verdict with log-actions accumulating (PRD v4 §2.3 precedence:
// block > challenge > log > pass; TR-05a).
//
// v0 slice (TR-05a): the vocabulary, the resolve semantics and the
// EvaluateTx shell — no detectors wired. The detector surface arrives with
// its own slices: S1 matcher (TR-16), S2 CRS (TR-07), S3 CEL seed + S0
// kernel hits (TR-05c), S4 schema (TR-13), S5 bots (TR-12/TR-19), S6
// rate/ban (TR-09/TR-10/TR-20), S7 ML (TR-21). Verdicts are LOGGED, not
// enforced, at this slice of the ladder (TR-05 posture).
package ladder

// Action is the §19.1 verdict action vocabulary (one per resolved verdict).
type Action string

const (
	// ActionAllow passes the tx (ladder term pass; non-decisive).
	ActionAllow Action = "allow"
	// ActionLog records the verdict without enforcement (non-decisive;
	// the walk continues — the v0 ladder slice is log-only, TR-05).
	ActionLog Action = "log"
	// ActionBlock, ActionChallenge and ActionBan are decisive: the first
	// fragment carrying one short-circuits the walk (§2.3 precedence —
	// first decisive wins).
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionBan       Action = "ban"
)

// Decisive reports whether a stops the ladder walk (§2.3: the first
// decisive verdict wins; allow/log never stop the walk).
func (a Action) Decisive() bool {
	switch a {
	case ActionBlock, ActionChallenge, ActionBan:
		return true
	}
	return false
}

// Phase is the processing phase a verdict was resolved in (§19.1
// Verdict.Phase; the ladder stages stamp the phase they fired in).
type Phase string

const (
	PhaseRequestHeaders  Phase = "request_headers"
	PhaseRequestBody     Phase = "request_body"
	PhaseResponseHeaders Phase = "response_headers"
	PhaseResponseBody    Phase = "response_body"
)

// RuleID names the rule or stage surface that produced a fragment
// (e.g. "shield:ban", "cel:seed-rate-shape", "crs:942100").
type RuleID string

// Stage is a fixed ladder position (§19.1: seven families, S0–S7 indexed;
// the numbering is a wire-level sorting contract and must never renumber).
type Stage int

const (
	StageKernel  Stage = iota // S0: kernel verdict cache + bans (TR-03 maps)
	StageMatcher              // S1: compiled matcher (TR-16; unwired in v0)
	StageCRS                  // S2: CRS reference evaluator (TR-07)
	StageCEL                  // S3: CEL rules over the §11.3 view (TR-02 pack)
	StageSchema               // S4: positive security (TR-13)
	StageBots                 // S5: bot detection (TR-12/TR-19)
	StageRateBan              // S6: rate + ban engine (TR-09/TR-10/TR-20)
	StageML                   // S7: ML scorer (TR-21)
	stageCount                // sentinel: number of ladder slots (S0–S7)
)

// Valid reports whether st indexes a real ladder slot (S0–S7).
func (st Stage) Valid() bool { return st >= 0 && st < stageCount }

// Verdict is the ladder's per-transaction accumulator (§19.1 Verdict, the
// slice-relevant fields: Features/CacheKey/BanInput/Telemetry land with
// their consuming stages — no speculative fields, the cel.Request rule).
// Stages return partial Verdicts (fragments); the Engine folds them in
// walk order.
type Verdict struct {
	Action Action   // resolved action (default ActionAllow)
	Rules  []RuleID // every contributing rule/stage, walk order
	Score  int64    // anomaly accumulator input (TR-09 consumes)
	Phase  Phase    // phase the current action was resolved in
}
