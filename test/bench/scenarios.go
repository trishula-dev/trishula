package bench

import (
	"fmt"
	"strconv"
	"strings"
)

// Scenario encodes one §17.2 benchmark-plan row. Driveable marks the
// scenarios measurable in hosted CI on the in-repo engine path; Plane
// names the runtime each scenario must run on; Gate names what keeps a
// non-driveable scenario out of CI today (empty = unblocked).
type Scenario struct {
	ID        string
	Name      string
	Driveable bool
	Plane     string // ci | lab | kernel | nightly | blocked
	Gate      string // the absent runtime the scenario waits on
}

// Recipe is one measured request cell inside a scenario: a
// deterministic request recipe bound to the §17.1 budget row it reports
// against. Iterations and Warmup bound the hosted-CI measurement cost.
type Recipe struct {
	ID          string
	Scenario    string
	Method      string
	URI         string
	Body        string // deterministic request body ("" = no body)
	ContentType string
	Attack      bool // the recipe carries attack payloads (CRS matches expected)
	BudgetID    string
	Iterations  int
	Warmup      int
}

// LoadScenarios returns the §17.2 scenario inventory: all nine rows,
// with the runtime classification. Rows 2, 3 and 7 measure in hosted CI
// on the committed CRS reference path; the rest carry the runtime they
// wait on, so a scenario stays named even when it cannot run here.
func LoadScenarios() ([]Scenario, error) {
	return []Scenario{
		{ID: "s17-2-1-baseline", Name: "Direct-to-pool via NGF (no WAF)", Plane: "lab", Gate: "NGF steering lab runtime"},
		{ID: "s17-2-2-inline-idle", Name: "Trishula in path, mostly-passing traffic", Driveable: true, Plane: "ci"},
		{ID: "s17-2-3-inline-steady", Name: "CRS at a realistic mixed request shape", Driveable: true, Plane: "ci"},
		{ID: "s17-2-4-shortcircuit", Name: "Verdict cost per altitude + cumulative cost curve", Plane: "kernel", Gate: "kernel altitude points (cached verdict, matcher)"},
		{ID: "s17-2-5-ban-ladder", Name: "ScoredWindowBan under mixed traffic; XDP ban-hit path", Plane: "kernel", Gate: "XDP ban-hit path under traffic"},
		{ID: "s17-2-6-shield-flood", Name: "SYN/UDP floods at a test NIC", Plane: "nightly", Gate: "bare-metal runners + flood scripts"},
		{ID: "s17-2-7-body-ladder", Name: "Body-size ladder through CRS", Driveable: true, Plane: "ci"},
		{ID: "s17-2-8-ml-ladder", Name: "ONNX scorer batch/latency curve", Plane: "blocked", Gate: "ML tier not landed"},
		{ID: "s17-2-9-hot-reload", Name: "RuleSet apply time-to-active + verdict integrity", Plane: "lab", Gate: "operator plane lab (M9 shape)"},
	}, nil
}

// Request-size targets for the body builders (bytes).
const (
	size1k  = 1024
	size8k  = 8 * 1024
	size64k = 64 * 1024
)

// buildJSON builds a deterministic JSON request body at or just over
// target bytes (an items array; the CRS surface never sees network
// noise in these cells).
func buildJSON(target int) string {
	var sb strings.Builder
	sb.WriteString(`{"items":[`)
	for i := 0; ; i++ {
		item := fmt.Sprintf(`{"id":%d,"name":"item-%d","tags":["a","b"]}`, i, i)
		if sb.Len()+len(item)+5 > target { // + comma + closing bracket tail
			break
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(item)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

// buildFormDense builds a deterministic urlencoded body at or just over
// target bytes: a dense key=pair sequence. This is the arg-dense deep-
// inspect surface the §17.1 engine budget currently fails on.
func buildFormDense(target int) string {
	var sb strings.Builder
	for i := 0; ; i++ {
		pair := "k" + strconv.Itoa(i) + "=v" + strconv.Itoa(i)
		if sb.Len()+len(pair)+1 > target {
			break
		}
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(pair)
	}
	return sb.String()
}

// Content types for the two body surfaces.
const (
	ctForm = "application/x-www-form-urlencoded"
	ctJSON = "application/json"
)

// Recipes returns the driveable request recipes for the CI-measurable
// scenarios (§17.2 rows 2, 3 and 7), each bound to the §17.1 row its
// measurement reports against. Iteration counts keep the whole CI-mode
// run at a few seconds of hosted-CI time.
func Recipes() ([]Recipe, error) {
	return []Recipe{
		// §17.2 row 2 — inline idle: passing traffic through the CRS walk.
		{ID: "idle-get", Scenario: "s17-2-2-inline-idle", Method: "GET", URI: "/?q=hello",
			BudgetID: "engine-inspect-8k", Iterations: 400, Warmup: 60},
		// §17.2 row 3 — inline steady: the 8KB full-CRS cell the §21 M2
		// metric binds, plus the attack shapes at the same surface.
		{ID: "steady-json-8k", Scenario: "s17-2-3-inline-steady", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctJSON, Body: buildJSON(size8k), BudgetID: "e2e-inline-hop-8k", Iterations: 240, Warmup: 20},
		{ID: "attack-xss-small", Scenario: "s17-2-3-inline-steady", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctForm, Body: `q=<script>alert(1)</script>&z=1`, Attack: true, BudgetID: "e2e-inline-hop-8k", Iterations: 300, Warmup: 40},
		{ID: "attack-sqli-small", Scenario: "s17-2-3-inline-steady", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctForm, Body: `q=1' OR '1'='1 --`, Attack: true, BudgetID: "e2e-inline-hop-8k", Iterations: 300, Warmup: 40},
		// §17.2 row 7 — body-size ladder: JSON body sizes through CRS,
		// plus the two arg-dense urlencoded shapes.
		{ID: "ladder-json-1k", Scenario: "s17-2-7-body-ladder", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctJSON, Body: buildJSON(size1k), BudgetID: "engine-inspect-8k", Iterations: 300, Warmup: 30},
		{ID: "ladder-json-8k", Scenario: "s17-2-7-body-ladder", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctJSON, Body: buildJSON(size8k), BudgetID: "engine-inspect-8k", Iterations: 240, Warmup: 20},
		{ID: "ladder-json-64k", Scenario: "s17-2-7-body-ladder", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctJSON, Body: buildJSON(size64k), BudgetID: "engine-inspect-64k", Iterations: 120, Warmup: 20},
		{ID: "ladder-form-dense-1k", Scenario: "s17-2-7-body-ladder", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctForm, Body: buildFormDense(size1k), BudgetID: "engine-inspect-8k", Iterations: 16, Warmup: 8},
		{ID: "ladder-form-dense-8k", Scenario: "s17-2-7-body-ladder", Method: "POST", URI: "/api/submit?q=1",
			ContentType: ctForm, Body: buildFormDense(size8k), BudgetID: "engine-inspect-8k", Iterations: 10, Warmup: 4},
	}, nil
}
