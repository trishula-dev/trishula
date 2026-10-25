package ladder

// TR-198 (issue #240) — the S3 auth-policy conformance. The design record
// (docs/design/auth-jwt-verdict.md, TR-45) places the claims policy at S3:
// after the CRS short-circuit, before schema gating. The contract the walk
// must honour (the record's vocabulary rules, adopted as written):
//
//   - request.auth.verified gates every allow path (section 4);
//   - the engine fills the names from the precondition channel only
//     (the gateway's verified identity metadata; the in-engine verifier
//     bundle is the optional second source);
//   - the channel miss stays verified=false; CEL reads the miss, no rule
//     panics;
//   - the S3 deny decision is the record's taxonomy row: block,
//     policy-selected (the claims gate; 403 class) against rule id
//     auth:<condition>.
//
// The conformance pack is the record's own example shape: the memberships
// rule ("read:orders" in request.auth.scopes) behind the verified gate.
import (
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// authConformancePack is the record's S3 example: the /orders/* route
// admits a verified identity carrying read:orders; every other shape on
// the route denies (the record's rule: verified=false gates the allow
// path; the deny id names the condition per the taxonomy).
const authConformancePack = `
rules:
  - id: auth:scope_insufficient
    name: orders-read-claims-gate
    description: >-
      The S3 claims gate: /orders/* admits a verified identity carrying
      read:orders; unverified or unscoped requests deny.
    action: enforce
    expression: |
      path.matches("/orders/*") &&
      (!request.auth.verified || !("read:orders" in request.auth.scopes))
`

// TestS3AuthPolicyConformance walks the record's S3 auth-policy cases
// through the assembled ladder (S0 clean + the S3 claims stage) and pins
// the resolved verdict per case.
func TestS3AuthPolicyConformance(t *testing.T) {
	pack, err := cel.ParseRulePack([]byte(authConformancePack))
	if err != nil {
		t.Fatalf("parse the auth conformance pack: %v", err)
	}

	authStage, err := NewAuthCEL(pack)
	if err != nil {
		t.Fatalf("wire the S3 claims stage: %v", err)
	}

	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(newShieldAdapterState().checker)); err != nil {
		t.Fatalf("wire S0: %v", err)
	}
	if err := e.Use(StageCEL, authStage); err != nil {
		t.Fatalf("wire the S3 claims stage into the slot: %v", err)
	}

	scopedClaims := map[string]any{
		"sub":    "u1",
		"iss":    "https://issuer.example",
		"aud":    "api",
		"scope":  "read:orders read:chat",
		"exp":    int64(1900000000),
		"tenant": "acme",
	}
	cases := []struct {
		name        string
		identity    *cel.VerifiedIdentity
		wantAction  Action
		wantRules   []RuleID
		wantBlocked bool
	}{
		{
			name:        "verified-false-gates-the-allow-path",
			identity:    &cel.VerifiedIdentity{Verified: false, Reason: "signature_invalid"},
			wantAction:  ActionBlock,
			wantRules:   []RuleID{"auth:scope_insufficient"},
			wantBlocked: true,
		},
		{
			name:       "verified-scoped-identity-admits",
			identity:   &cel.VerifiedIdentity{Verified: true, Claims: scopedClaims},
			wantAction: ActionAllow,
			wantRules:  nil,
		},
		{
			name: "verified-unscoped-identity-denies",
			identity: &cel.VerifiedIdentity{
				Verified: true,
				Claims: map[string]any{
					"sub": "u2", "iss": "https://issuer.example", "aud": "api",
					"scope": "read:chat", "exp": int64(1900000000),
				},
			},
			wantAction:  ActionBlock,
			wantRules:   []RuleID{"auth:scope_insufficient"},
			wantBlocked: true,
		},
		{
			// The channel miss: verified stays false (the record's zero),
			// so a gated route denies instead of admitting unheard.
			name:        "missing-channel-denies-fail-closed",
			identity:    nil,
			wantAction:  ActionBlock,
			wantRules:   []RuleID{"auth:scope_insufficient"},
			wantBlocked: true,
		},
	}
	for _, tc := range cases {
		tx := &ingest.TxContext{
			Key:      ingest.FlowKey{Family: ingest.FamilyV4},
			Metadata: map[string]string{},
		}
		if err := AttachView(tx, &cel.Request{Method: "GET", Path: "/orders/7"}); err != nil {
			t.Fatalf("[%s] attach view: %v", tc.name, err)
		}
		if tc.identity != nil {
			if err := AttachVerifiedIdentity(tx, tc.identity); err != nil {
				t.Fatalf("[%s] attach identity: %v", tc.name, err)
			}
		}
		v := e.EvaluateTx(tx)
		if v == nil {
			t.Fatalf("[%s] the walk produced no verdict", tc.name)
		}
		if v.Action != tc.wantAction {
			t.Errorf("[%s] action: got %q, want %q (the S3 gate must hold the allow path)", tc.name, v.Action, tc.wantAction)
		}
		if got, want := len(v.Rules), len(tc.wantRules); got != want {
			t.Errorf("[%s] rules: got %v, want %v", tc.name, v.Rules, tc.wantRules)
		} else {
			for i := range tc.wantRules {
				if v.Rules[i] != tc.wantRules[i] {
					t.Errorf("[%s] rules[%d]: got %q, want %q", tc.name, i, v.Rules[i], tc.wantRules[i])
				}
			}
		}
		if tc.wantBlocked && v.Action != ActionBlock {
			t.Errorf("[%s] the allow path leaked behind a deny gate: got %q, want block", tc.name, v.Action)
		}
		if v.Phase != PhaseRequestHeaders {
			t.Errorf("[%s] phase: got %q, want request_headers", tc.name, v.Phase)
		}
	}
}
