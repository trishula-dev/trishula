// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package ladder

// TR-198 (issue #240) — the S3 claims-policy wiring, in one file so the
// S-slot wiring neighborhood stays rebase-friendly (the record:
// docs/design/auth-jwt-verdict.md, adopted as written).
//
// S3 is the one ladder stage that evaluates auth policy: after the CRS
// short-circuit, before schema gating (the record's ladder map, section 3).
// The stage composes the seed CEL evaluation (s0_cel.go's CELEval) with the
// two claim sources and the promotion posture:
//
//   - the precondition channel: the gateway's verified identity metadata
//     (AttachVerifiedIdentity; the channel unit is the VerifiedIdentity).
//     No identity header ever feeds the view — the record's rule 2;
//   - the optional in-engine verifier bundle riding the rule pack (the
//     pack's AuthVerifier; the operator supplies it, TR-198). The bearer
//     token bytes reach it over the authorization header's metadata slot;
//   - ResolveIdentity runs ONE order: channel, then bundle, then the
//     verified=false zero. The miss never panics CEL (the record's rule 3);
//   - the deny decision: a matched rule declaring `action: enforce`
//     resolves DECISIVE block at S3 (the record's taxonomy: block,
//     policy-selected). The seed posture (log-only) stays the default: a
//     stage whose pack carries no matched enforce rule folds exactly as
//     TestCELEvalMatchLogsPinsLogOnly pins it. `action: ban` keeps its
//     consult-surface semantics (TR-195) and never lifts here.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// verifiedIdentityMetaKey is the tx-Metadata slot carrying the gateway's
// verified identity metadata (JSON-encoded cel.VerifiedIdentity). The
// slot is the channel contract until the typed engine plumbing lands
// (the AttachView pattern).
const verifiedIdentityMetaKey = "auth_identity_json"

// bearerHeaderMetaKey is the tx-Metadata slot carrying the authorization
// header's RAW value: the token bytes ride it to the OPTIONAL in-engine
// verifier (the record's rule 2: the header carries token bytes to the
// verifier; it never reads as a claim source — claim values never parse
// out of this slot).
const bearerHeaderMetaKey = "authorization"

// AttachVerifiedIdentity stores the gateway's verified identity metadata
// on the tx (engine plumbing + tests; JSON keeps the slot decoupled from
// the claims surface).
func AttachVerifiedIdentity(tx *ingest.TxContext, vi *cel.VerifiedIdentity) error {
	if tx == nil || vi == nil {
		return fmt.Errorf("attach verified identity: nil tx or identity")
	}
	if tx.Metadata == nil {
		tx.Metadata = map[string]string{}
	}
	b, err := json.Marshal(vi)
	if err != nil {
		return fmt.Errorf("attach verified identity: %w", err)
	}
	tx.Metadata[verifiedIdentityMetaKey] = string(b)
	return nil
}

// VerifiedIdentityFrom reads the attached identity metadata back
// (nil = none attached or unusable bytes: an unusable channel is the miss,
// the verified=false zero — never a fabricated identity).
func VerifiedIdentityFrom(tx *ingest.TxContext) *cel.VerifiedIdentity {
	if tx == nil {
		return nil
	}
	raw, ok := tx.Metadata[verifiedIdentityMetaKey]
	if !ok || raw == "" {
		return nil
	}
	var vi cel.VerifiedIdentity
	if err := json.Unmarshal([]byte(raw), &vi); err != nil {
		return nil
	}
	return &vi
}

// AuthCEL is the S3 claims-policy stage: the seed CEL evaluation wrapped
// with the verified-identity resolution and the promotion posture
// (matched enforce rules = the deny decision). Stage() pins S3 through the
// embedded evaluator's own pin, so Engine.Use(StageCEL, ...) wires exactly
// the S3 slot.
type AuthCEL struct {
	Evaluator // the underlying CEL stage (CELEval): the pack evaluation + the log fold
	pack      *cel.RulePack
	verifier  *cel.Verifier
	now       cel.Clock
}

// NewAuthCEL wires the S3 claims stage over a pack. The pack carries the
// deny rules AND (optionally) the verifier bundle. An empty or nil pack is
// the wiring error the CELEval surface refuses (an empty-walk S3 is the
// silent-skip shape).
func NewAuthCEL(pack *cel.RulePack) (*AuthCEL, error) {
	if pack == nil || len(pack.Rules) == 0 {
		return nil, fmt.Errorf("auth stage: empty rule pack (wiring error, not an empty opinion)")
	}
	a := &AuthCEL{
		Evaluator: NewCELEval(pack),
		pack:      pack,
		verifier:  pack.Verifier(),
		now:       cel.DefaultClock(),
	}
	for i := range pack.Rules {
		pack.Rules[i].SetClock(a.now)
	}
	return a, nil
}

// tokenOf reads the token bytes off the authorization slot: the raw
// header value's Bearer scheme prefix strips (RFC 6750; the scheme is not
// part of the token the verifier sees). Non-bearer schemes read the miss
// (the bundle verifies bearer tokens only).
func (a *AuthCEL) tokenOf(tx *ingest.TxContext) string {
	if tx == nil || tx.Metadata == nil {
		return ""
	}
	raw := tx.Metadata[bearerHeaderMetaKey]
	if raw == "" {
		return ""
	}
	scheme, tok, _ := strings.Cut(raw, " ")
	if !strings.EqualFold(strings.TrimSpace(scheme), "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

// Evaluate resolves the verified identity onto the view, runs the pack,
// and lifts the claims decision: the seed fold's log fragment stays log
// unless a matched rule declares enforce — the record's block,
// policy-selected, then lands decisive at S3.
func (a *AuthCEL) Evaluate(tx *ingest.TxContext) *Verdict {
	view := TxView(tx)
	if view != nil {
		view.Auth = cel.ResolveIdentity(VerifiedIdentityFrom(tx), a.verifier, a.tokenOf(tx), a.now())
		if err := AttachView(tx, view); err != nil {
			// Attachment failure = no resolved view for the walk this
			// stage would trust; the stage gives no opinion and never
			// fabricates a verdict (fail safe, the parse-miss posture).
			return nil
		}
	}
	frag := a.Evaluator.Evaluate(tx)
	if frag == nil {
		return nil
	}
	return a.liftClaimsDecision(frag)
}

// liftClaimsDecision promotes a matched enforce rule into the decisive
// block the record's S3 taxonomy row carries (block, policy-selected).
// Error evidence (:error ids) stays out of the decision scan; log and
// none actions stay the seed fold (the shadow posture); ban stays the
// consult surface's direct-ban flow (TR-195) and never lifts here.
func (a *AuthCEL) liftClaimsDecision(frag *Verdict) *Verdict {
	for _, id := range frag.Rules {
		if id == "" || strings.HasSuffix(string(id), ":error") {
			continue
		}
		for i := range a.pack.Rules {
			if string(a.pack.Rules[i].ID) == string(id) && a.pack.Rules[i].Action == cel.ActionEnforce {
				frag.Action = ActionBlock
				return frag
			}
		}
	}
	return frag
}
