// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package operator

// TR-198 (issue #240) — the consult path carries the request.auth
// vocabulary: Load re-parses the packs' verifier bundle (fail closed on a
// bad key), the Eval exposes it, and Decide decides over a filled view.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// consultAuthPackYaml is the fixture pack: the HS256 bundle + the deny
// rule over the /orders/* route family.
const consultAuthPackYaml = `
verifier:
  hs256SecretsHex:
    - 9f86d081884c7d659a2feaa0c55ad015
rules:
  - id: auth:scope_insufficient
    name: orders-read-claims-gate
    description: gates /orders/* on verified + read:orders
    action: enforce
    expression: |
      path.matches("/orders/*") &&
      (!request.auth.verified || !("read:orders" in request.auth.scopes))
`

// hsSignHex signs a payload string with the hex key (the consult test's
// own token builder; the engine never issues tokens).
func hsSignHex(keyHex, head, payload string) string {
	key, _ := hex.DecodeString(keyHex)
	in := base64.RawURLEncoding.EncodeToString([]byte(head)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func loadAuthBundle(t *testing.T) *Eval {
	t.Helper()
	pack, err := cel.ParseRulePack([]byte(consultAuthPackYaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	bundle := Bundle{
		FormatVersion: BundleFormatVersion,
		Tenant:        "dx1",
		Policy:        Policy{DefaultAction: v1alpha1.DefaultActionPass},
		KernelValues:  &KernelValues{ACL4: map[string]string{}, ACL6: map[string]string{}, Verdicts: map[string]string{}},
		RulePacks:     []cel.RulePack{*pack},
	}
	digests, err := packDigests(bundle.RulePacks)
	if err != nil {
		t.Fatalf("digests: %v", err)
	}
	bundle.RulePackDigests = digests
	e, err := Load(bundle)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return e
}

func TestLoadMergesPackVerifiers(t *testing.T) {
	e := loadAuthBundle(t)
	if e.Verifier() == nil {
		t.Fatal("Load dropped the pack's verifier bundle")
	}
}

func TestLoadRejectsBadVerifierKey(t *testing.T) {
	pack, err := cel.ParseRulePack([]byte(consultAuthPackYaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pack.AuthVerifier = &cel.VerifierConfig{HS256SecretsHex: []string{"not-hex"}}
	bundle := Bundle{
		FormatVersion: BundleFormatVersion,
		Tenant:        "dx1",
		KernelValues:  &KernelValues{ACL4: map[string]string{}, ACL6: map[string]string{}, Verdicts: map[string]string{}},
		RulePacks:     []cel.RulePack{*pack},
	}
	digests, err := packDigests(bundle.RulePacks)
	if err != nil {
		t.Fatalf("digests: %v", err)
	}
	bundle.RulePackDigests = digests
	if _, err := Load(bundle); err == nil {
		t.Fatal("a bad verifier key must fail the load (fail closed)")
	}
}

func TestConsultDecidesOnVerifiedIdentity(t *testing.T) {
	e := loadAuthBundle(t)
	const keyHex = "9f86d081884c7d659a2feaa0c55ad015"
	cases := []struct {
		name      string
		token     string
		wantBlock bool
		ruleID    string
	}{
		// verified=false on the gated route: the allow path is gated.
		{"unverified-blocks", "", true, "auth:scope_insufficient"},
		{"broken-token-blocks", "x.y.z", true, "auth:scope_insufficient"},
		{"verified-unscoped-blocks", hsSignHex(keyHex, `{"alg":"HS256"}`, `{"sub":"u2","scope":"read:chat"}`), true, "auth:scope_insufficient"},
		{"verified-scoped-forwards", hsSignHex(keyHex, `{"alg":"HS256"}`, `{"sub":"u1","scope":"read:orders"}`), false, ""},
	}
	for _, tc := range cases {
		req := cel.Request{Method: "GET", Path: "/orders/7"}
		// The consult view fill mirrors consultView's contract (cmd side):
		// the bundle verifier over the bearer bytes at the wall epoch. The
		// token bytes travel scheme-stripped (RFC 6750).
		req.Auth = cel.ResolveIdentity(nil, e.Verifier(), tc.token, nowUnix())
		d, err := e.Decide(req)
		if err != nil {
			t.Fatalf("[%s] decide: %v", tc.name, err)
		}
		if tc.wantBlock {
			if d.Action != v1alpha1.DefaultActionBlock || d.RuleID != tc.ruleID {
				t.Errorf("[%s] got %+v, want block by %s (the allow path must stay gated at verified=false)", tc.name, d, tc.ruleID)
			}
			continue
		}
		if d.Action != v1alpha1.DefaultActionPass || d.RuleID != "" {
			t.Errorf("[%s] got %+v, want pass by the default (no gate held)", tc.name, d)
		}
	}
}

// nowUnix pins the test epoch (the consult view's clock input).
func nowUnix() int64 { return int64(1000) }
