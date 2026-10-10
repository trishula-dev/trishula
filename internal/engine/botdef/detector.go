package botdef

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// bot-def tx attachment keys (the TR-29 supply surface; JSON keeps ingest
// decoupled from botdef, same pattern as ladder.AttachView's viewMetaKey).
const (
	chMetaKey  = "botdef_client_hello_json"
	hvMetaKey  = "botdef_header_view_json"
	labLogMeta = "botdef_lab_log_line"
)

// Detector is the §12 bot detector: a ladder Evaluator at the fixed S5
// StageBots slot. v0 emits ONLY log-tier fragments (PRD §12: single-detector
// matches log and score — consensus/blocking arrives with TR-19's merge
// policy). Detached transactions (no attached ClientHelloSummary and/or
// HeaderView — the state of every tx until TR-15/29 wire the extraction)
// produce NO fragment; the S5 stage stays silent rather than fabricate a
// verdict. No-op when the engine is unwired (ladder skips empty slots).
type Detector struct{}

// ruleBotJA4 / ruleBotHeaders are the §12 (detector_id, evidence) rule ids
// the S5 fragment carries (ladder.Rules, walk order).
const (
	ruleBotJA4     ladder.RuleID = "bot:ja4"
	ruleBotHeaders ladder.RuleID = "bot:headers"
)

// botScoreToolEvidence / botScoreJa4Prior are the v0 score contributions
// (log-tier evidence accumulation feeding the ban engine per §12 — values
// v0-pinned, tunable when the merge policy lands).
const (
	botScoreToolEvidence = 7 // header plane classifies tool-ish
	botScoreJa4Prior     = 2 // JA4 present (a prior per §12.3, never a verdict)
)

// NewDetector builds the bot detector (stateless v0).
func NewDetector() *Detector { return &Detector{} }

// Stage pins the fixed §19.1 ladder position: S5 bots.
func (d *Detector) Stage() ladder.Stage { return ladder.StageBots }

// Evaluate walks the two v0 detectors over the attached evidence and folds
// the §12 evidence into one S5 fragment (always log-tier at v0). Wire
// contract:
//
//   - JA4 evidence: the computed fingerprint is the bot-vs-browser PRIOR,
//     not a verdict by itself (§12.3 honest limits — a hash without the
//     tooling DB cannot assert); it accumulates rule + prior score.
//   - Header evidence: the header-plane classification (tool-ish vs
//     browser-ish) is a direct per-request signal; tool-ish logs AND
//     scores.
//   - Both planes agreeing on "tool" still logs (v0 single-detector
//     posture; the consensus rule is TR-19's merge policy).
//
// A nil fragment (nothing attached) keeps the walk moving — S5 never
// fabricates an opinion from absent evidence.
func (d *Detector) Evaluate(tx *ingest.TxContext) *ladder.Verdict {
	if tx == nil {
		return nil
	}
	ch, hv := ClientHelloOf(tx), HeaderViewOf(tx)
	if ch == nil && hv == nil {
		return nil
	}

	v := &ladder.Verdict{Action: ladder.ActionLog, Phase: ladder.PhaseRequestHeaders}

	if ch != nil {
		r := ja4f(ch)
		v.Rules = append(v.Rules, ruleBotJA4)
		v.Score += botScoreJa4Prior // prior: the fingerprint exists, no DB match v0
		// Record the JA4 prior on the tx so the lab log survives the
		// detached-render path (LabLogLine re-derives when evidence is
		// still attached; Metadata carries it when it is not).
		if tx.Metadata == nil {
			tx.Metadata = map[string]string{}
		}
		tx.Metadata["botdef_ja4"] = r.JA4
	}

	if hv != nil {
		hfp := headerFingerprint(hv)
		if tx.Metadata == nil {
			tx.Metadata = map[string]string{}
		}
		tx.Metadata["botdef_hf"] = hfp.Hash
		if hfp.Toolish {
			v.Rules = append(v.Rules, ruleBotHeaders)
			v.Score += botScoreToolEvidence
			tx.Metadata["botdef_class"] = "tool"
		} else {
			tx.Metadata["botdef_class"] = "browser"
		}
	}
	return v
}

// AttachClientHello stores one terminated-hop ClientHello summary on the tx
// for the S5 stage to find (same pattern as ladder.AttachView). The
// kernel/ingest child (TR-29) calls this once its extraction lands.
func AttachClientHello(tx *ingest.TxContext, ch *ClientHelloSummary) error {
	return attachBotJSON(tx, chMetaKey, ch)
}

// ClientHelloOf reads a summary back off the tx (nil = none attached).
func ClientHelloOf(tx *ingest.TxContext) *ClientHelloSummary {
	ch, ok := readBotJSON[ClientHelloSummary](tx, chMetaKey)
	if !ok {
		return nil
	}
	return ch
}

// AttachHeaderView stores one ordered header view on the tx (same pattern;
// the header fingerprint consumes it). The Values lookup map, when nil, is
// rebuilt from the wire pairs on attach so the round-trip is complete.
func AttachHeaderView(tx *ingest.TxContext, hv *HeaderView) error {
	if hv != nil && hv.Values == nil {
		hv.Values = make(map[string]string, len(hv.Headers))
		for _, kv := range hv.Headers {
			hv.Values[lower(kv[0])] = kv[1]
		}
	}
	return attachBotJSON(tx, hvMetaKey, hv)
}

// HeaderViewOf reads a header view back off the tx (nil = none attached).
func HeaderViewOf(tx *ingest.TxContext) *HeaderView {
	hv, ok := readBotJSON[HeaderView](tx, hvMetaKey)
	if !ok {
		return nil
	}
	return hv
}

// LabLogLine renders one §12 lab-log verdict line (the acceptance surface:
// a curl-vs-browser pair through the wired detector produces two lines with
// distinct ja4= and hf= values, in the DX1 verdict-log field order):
//
//	verdict src=<ip:port> dst=<ip:port> action=log stage=s5 detectors=<set>
//	  ja4=<ja4> hf=<fp> class=<tool|browser|none> rules=<bot:ja4,bot:headers> score=<n>
//
// Requires the tx to have WALKED by a wired Detector (the rendered line
// reflects the verdict state the walk left in Metadata); an un-walked tx
// renders "" and the fixture/test path runs the walk first.
func LabLogLine(tx *ingest.TxContext) string {
	if tx == nil || len(tx.Metadata) == 0 {
		return ""
	}
	if line, ok := tx.Metadata[labLogMeta]; ok && line != "" {
		return line
	}
	ja4, hf, cls := tx.Metadata["botdef_ja4"], tx.Metadata["botdef_hf"], tx.Metadata["botdef_class"]
	if ja4 == "" && hf == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("verdict ")
	sb.WriteString("src=" + flowEndpoint(tx.Key.SrcIP[:], tx.Key.SrcPort, tx.Key.Family) + " ")
	sb.WriteString("dst=" + flowEndpoint(tx.Key.DstIP[:], tx.Key.DstPort, tx.Key.Family) + " ")
	sb.WriteString("action=log stage=s5 ")
	det := "ja4"
	if hf != "" {
		det = "ja4+headers"
	}
	sb.WriteString("detectors=" + det + " ")
	if ja4 != "" {
		sb.WriteString("ja4=" + ja4 + " ")
	}
	if hf != "" {
		sb.WriteString("hf=" + hf + " ")
	}
	sb.WriteString("class=" + cls + " ")
	// score-derived rules line mirrors the fragment the walk produced
	var rules string
	if hf != "" && cls == "tool" {
		rules = "bot:ja4,bot:headers"
	} else {
		rules = "bot:ja4"
	}
	score := botScoreJa4Prior
	if hf != "" && cls == "tool" {
		score += botScoreToolEvidence
	}
	sb.WriteString("rules=" + rules + " ")
	sb.WriteString(fmt.Sprintf("score=%d", score))
	line := sb.String()
	if tx.Metadata == nil {
		tx.Metadata = map[string]string{}
	}
	tx.Metadata[labLogMeta] = line
	return line
}

// flowEndpoint renders one FlowKey endpoint (v4 form; v6 arrives with the
// dual-stack ingest planes).
func flowEndpoint(ip []byte, port uint16, family uint8) string {
	if family == ingest.FamilyV6 {
		var a [16]byte
		copy(a[:], ip)
		return netip.AddrFrom16(a).String() + ":" + fmt.Sprintf("%d", port)
	}
	var a [4]byte
	copy(a[:], ip)
	return netip.AddrFrom4(a).String() + ":" + fmt.Sprintf("%d", port)
}

// attachBotJSON marshals one attachment onto the tx Metadata.
func attachBotJSON(tx *ingest.TxContext, key string, val any) error {
	if tx == nil {
		return fmt.Errorf("botdef: attach %s: nil tx", key)
	}
	if val == nil {
		return fmt.Errorf("botdef: attach %s: nil value", key)
	}
	b, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("botdef: attach %s: %w", key, err)
	}
	if tx.Metadata == nil {
		tx.Metadata = map[string]string{}
	}
	tx.Metadata[key] = string(b)
	return nil
}

// readBotJSON reads one attachment back off the tx Metadata. The target
// type is named at the call site via an explicit conversion helper — v0
// has exactly two attachment kinds, so two small wrappers carry the type.
func readBotJSON[T any](tx *ingest.TxContext, key string) (*T, bool) {
	if tx == nil {
		return nil, false
	}
	raw, ok := tx.Metadata[key]
	if !ok || raw == "" {
		return nil, false
	}
	var v T
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, false
	}
	return &v, true
}
