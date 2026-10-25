package ingest

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TR-194 (issue #236): the FlowEvent wire contract bound to the C source
// (the AGENTS.md layer map: a kernel wire contract lives pinned at the C).
// bpf/flow_tc.c's struct flow_event is the reference; decode.go reads the
// same member order and the same stage-bit macros. A C-side drift fails
// HERE, before any ring decode (the record's §5 freeze: bytes 0–199
// byte-identical, `stages` appended last after the path hint).

// flowTCSource reads the C producer source relative to this package.
func flowTCSource(t testing.TB) string {
	t.Helper()
	raw, err := os.ReadFile("../../../bpf/flow_tc.c")
	if err != nil {
		t.Fatalf("read bpf/flow_tc.c: %v", err)
	}
	return string(raw)
}

// cMembers returns flow_event's member names in declaration order
// (comments stripped first; multi-name lines expand; array suffixes drop).
func cMembers(t testing.TB, csrc string) []string {
	t.Helper()
	match := regexp.MustCompile(`(?s)struct flow_event \{(.*?)\};`).FindStringSubmatch(
		regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(csrc, " "))
	if len(match) < 2 || match[1] == "" {
		t.Fatal("bpf/flow_tc.c: struct flow_event block not found")
	}
	var names []string
	for _, line := range strings.Split(match[1], "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\t", " "))
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ";")
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue // the struct keyword line: no members
		}
		for _, f := range fields[1:] { // field 0 = the type token
			name := strings.Split(strings.Split(f, "[")[0], ",")[0]
			if name == "" {
				continue
			}
			names = append(names, name)
		}
	}
	return names
}

// cMacro returns a #define integer value from the C source (parens
// expressions resolve over the already-read names — `A | B` forms only).
func cMacro(t testing.TB, csrc, name string) uint64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(name) + `\s+(.+?)\s*$`)
	m := re.FindStringSubmatch(csrc)
	if m == nil {
		t.Fatalf("bpf/flow_tc.c: no #define %s", name)
	}
	expr := m[1]
	val := func(tok string) uint64 {
		if v, err := strconv.ParseUint(tok, 0, 64); err == nil {
			return v
		}
		inner := cMacro(t, csrc, tok)
		return inner
	}
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		parts := strings.Split(strings.Trim(expr, "()"), "|")
		var out uint64
		for _, p := range parts {
			out |= val(strings.TrimSpace(p))
		}
		return out
	}
	return val(expr)
}

func TestFlowEventWireParity(t *testing.T) {
	csrc := flowTCSource(t)

	t.Run("member order + stages last (the record's append-after freeze)", func(t *testing.T) {
		want := []string{
			"ts_ns", "saddr_v4", "saddr_v6", "daddr_v4", "daddr_v6",
			"sport", "dport", "tcp_flags", "mark", "payload_len",
			"http_seen", "h2_preface", "tls_seen", "family", "path_hint", "stages",
		}
		got := cMembers(t, csrc)
		if len(got) != len(want) {
			t.Fatalf("flow_event members = %v, want %v names", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("flow_event member %d = %q, want %q (byte 0–199 stay frozen; stages appends LAST)", i, got[i], want[i])
			}
		}
		if got[len(got)-1] != "stages" {
			t.Fatalf("stages is not the last member: %v", got)
		}
	})

	t.Run("the C stage macros == the Go bit vocabulary", func(t *testing.T) {
		cases := []struct {
			macro string
			want  uint64
		}{
			{"TC_ST_CLASSIFY", StageTCClassify},
			{"TC_ST_BAN", StageTCBan},
			{"TC_ST_FASTPATH", StageTCFastpath},
			{"TC_STAGES_BASE", StageTCClassify | StageTCBan},
		}
		for _, tc := range cases {
			if got := cMacro(t, csrc, tc.macro); got != tc.want {
				t.Fatalf("C %s = %#x, want %#x (the C macros and the Go bits name one vocabulary)", tc.macro, got, tc.want)
			}
		}
		if StageBitsKernel != 0x7F {
			t.Fatalf("StageBitsKernel = %#x, want 0x7F (bits 0–6; 57 bits reserved)", StageBitsKernel)
		}
	})
}
