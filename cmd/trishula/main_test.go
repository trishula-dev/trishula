package main

import (
	"bytes"
	"strings"
	"testing"
)

// TR-02 (issue #2): cmd/trishula is the skeleton entrypoint. The selftest
// tracer proves the skeleton end-to-end: seed rule pack in, §11.3 fixture
// cases evaluated, verdicts on stdout, exit code reflects the outcome.
const (
	seedPack     = "../../rules/cel/seed.yaml"
	sampleCases  = "../../internal/engine/cel/testdata/sample_request.yaml"
)

func TestSelftestHappyPath(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"--selftest", "--rules", seedPack, "--requests", sampleCases}, &out)
	if code != 0 {
		t.Fatalf("selftest exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "selftest OK") {
		t.Fatalf("selftest output lacks 'selftest OK': %q", out.String())
	}
	// One line per fixture case (4 cases): the verdict is visible, not hidden.
	if n := strings.Count(out.String(), "\n"); n < 4 {
		t.Fatalf("selftest printed %d lines, want >=4 (one per case): %q", n, out.String())
	}
}

func TestSelftestFailsOnMissingRulePack(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"--selftest", "--rules", "no/such/pack.yaml", "--requests", sampleCases}, &out)
	if code == 0 {
		t.Fatalf("missing rule pack must exit nonzero, output=%q", out.String())
	}
}

func TestNoModeExitsUsage(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{}, &out); code == 0 {
		t.Fatalf("no-mode run must exit nonzero (usage)")
	}
}
