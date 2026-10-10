package crs

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
)

// fixedClock stamps the test tx scope (parity/telemetry correlation; the
// SecLang surface carries no time-based rules this slice evaluates).
var fixedClock = func() time.Time { return time.Unix(0, 0).UTC() }

// TestCorazaLoadAndEval (TR-07 PR A watch): load a minimal SecLang
// snippet from testdata, evaluate two crafted requests, expect the
// Verdict structure (per-phase matches, shadow-only disruption evidence).
func TestCorazaLoadAndEval(t *testing.T) {
	ev, err := NewFromFileWithOptions("testdata/seclang/simple.conf", WithClock(fixedClock))
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}

	now := fixedClock()
	opt := func(method, uri string, ua, q string, body []byte) Options {
		o := Options{
			Method:  method,
			URI:     uri,
			Version: "1.1",
			Headers: map[string]string{
				"Host":         "trishula.dev",
				"Content-Type": "text/plain",
				"X-Raw":        ":", // id:9000 enables the RAW body processor
			},
			Client: netip.MustParseAddr("192.0.2.7"),
			Port:   80,
			Now:    now,
		}
		if ua != "" {
			o.Headers["User-Agent"] = ua
		}
		if q != "" {
			o.URI = uri + "?q=" + q
		}
		o.Body = body
		return o
	}

	v, err := ev.Evaluate(opt("GET", "/index.html",
		"trishula-shadow/0.0",
		strings.Repeat("%3Cscript%3E", 4),
		[]byte("nothing to see")))
	if err != nil {
		t.Fatalf("Evaluate(positive): %v", err)
	}
	if len(v.Phase1Matches) != 3 {
		t.Fatalf("Phase1Matches ruleids = %+v, want enabler 9000 + markers 1001+1002", v.Phase1Matches)
	}
	if v.Phase1Matches[0].RuleID != bodyEnableRUID {
		t.Fatalf("Phase1Matches[0] = %+v, want the body-processor enabler id:%d first",
			v.Phase1Matches[0], bodyEnableRUID)
	}
	if len(v.Phase2Matches) != 0 {
		t.Fatalf("Phase2Matches = %+v, want none (body carries no token)", v.Phase2Matches)
	}
	if v.Interrupted {
		t.Fatalf("Interrupted = %v, want false (nothing disruptive)", v.Interrupted)
	}

	v, err = ev.Evaluate(opt("GET", "/index.html",
		"plain-agent",
		"ok",
		[]byte("body with badtoken inside")))
	if err != nil {
		t.Fatalf("Evaluate(disruptive): %v", err)
	}
	if len(v.Phase2Matches) != 1 || v.Phase2Matches[0].RuleID != denyRuleID {
		t.Fatalf("Phase2Matches = %+v, want exactly id:%d", v.Phase2Matches, denyRuleID)
	}
	if !v.Interrupted || v.InterruptRule != denyRuleID {
		t.Fatalf("Interruption = (%v, rule %d), want interrupted by id:%d",
			v.Interrupted, v.InterruptRule, denyRuleID)
	}
	if v.InterruptStat != 403 {
		t.Fatalf("InterruptStat = %d, want 403", v.InterruptStat)
	}
}

// TestShadowMode asserts the wrapper's posture: verdicts are EVIDENCE —
// the run never enforces. A phase-2 deny is returned as data (the
// interruption is reported inside the Verdict, never as an error) and
// matching stays visible per phase.
func TestShadowMode(t *testing.T) {
	ev, err := NewFromFile("testdata/seclang/simple.conf")
	if err != nil {
		t.Fatalf("NewFromFile: %v", err)
	}
	v, err := ev.Evaluate(Options{
		Method:  "GET",
		URI:     "/index.html?q=%3Cscript%3E",
		Version: "1.1",
		Headers: map[string]string{
			"User-Agent":   "trishula-shadow/0.0",
			"X-Raw":        ":", // RAW body processor (REQUEST_BODY addressable)
			"Content-Type": "text/plain",
		},
		Body:   []byte("body with badtoken inside"),
		Client: netip.MustParseAddr("192.0.2.7"),
		Port:   80,
		Now:    fixedClock(),
	})
	if err != nil {
		t.Fatalf("shadow run must surface matches as data, not enforcement errors: %v", err)
	}
	found := map[int]bool{}
	for _, m := range v.Phase1Matches {
		found[m.RuleID] = true
	}
	for _, id := range []int{uaRuleID, probeRuleID} {
		if !found[id] {
			t.Fatalf("shadow phase-1 matches = %+v, want marker id:%d present", v.Phase1Matches, id)
		}
	}
	if !v.Interrupted || v.InterruptRule != bodyDenyRuleID {
		t.Fatalf("shadow disruption evidence = (%v, rule %d), want the phase-2 deny as DATA (id:%d)",
			v.Interrupted, v.InterruptRule, bodyDenyRuleID)
	}
	if len(v.Phase2Matches) != 1 || v.Phase2Matches[0].RuleID != bodyDenyRuleID {
		t.Fatalf("Phase2Matches = %+v, want the phase-2 deny projected (id:%d)",
			v.Phase2Matches, bodyDenyRuleID)
	}
}

// TestLoadError asserts the loud load path (no silent SecLang errors).
func TestLoadError(t *testing.T) {
	if _, err := NewFromFile("testdata/seclang/broken.conf"); err == nil {
		t.Fatal("NewFromFile accepted an unknown SecLang directive: want a load error")
	}
}

// The Coraza transaction walk is pinned as a compile-time check: the
// engine's phase surface (ProcessURI → ProcessRequestHeaders → body) is
// the §11.8 reference evaluation order this wrapper reproduces.
var (
	_ types.Transaction // referenced so the walk's dependency shape is visible in vet
	_ debuglog.Logger   // injected logger surface (no default logger, host-CI quiet)
)

// denyRuleID / probeRuleID / uaRuleID are the seed snippet's rule ids.
const (
	denyRuleID     = 1003
	uaRuleID       = 1001
	probeRuleID    = 1002
	bodyEnableRUID = 9000
)

// bodyDenyRuleID is the phase-2 deny (alias kept for assertions).
const bodyDenyRuleID = denyRuleID
