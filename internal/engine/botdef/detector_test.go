package botdef

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// labPair builds the acceptance pair: two transactions, one carrying a
// curl fingerprint + tool headers, one carrying a Chrome fingerprint +
// browser headers — the exact state a terminated-hop ingest lands after
// TR-15/29 wire the extraction.
func labPair(t *testing.T) (curlTx, browserTx *ingest.TxContext) {
	t.Helper()
	f, err := os.Open("testdata/curl_vs_browser.json")
	if err != nil {
		t.Fatalf("open header pair: %v", err)
	}
	defer f.Close()
	var fixture struct {
		BrowserHeaders struct {
			Method  string      `json:"method"`
			Headers [][2]string `json:"headers"`
		} `json:"browser_headers"`
		ToolHeaders struct {
			Method  string      `json:"method"`
			Headers [][2]string `json:"headers"`
		} `json:"tool_headers"`
	}
	if err := json.NewDecoder(f).Decode(&fixture); err != nil {
		t.Fatalf("decode header pair: %v", err)
	}

	vf, err := os.Open("testdata/ja4_vectors.json")
	if err != nil {
		t.Fatalf("open ja4 vectors: %v", err)
	}
	defer vf.Close()
	type labVector = struct {
		Name                string   `json:"name"`
		Transport           string   `json:"transport"`
		LegacyVersion       uint16   `json:"legacy_version"`
		SupportedVersions   []uint16 `json:"supported_versions"`
		SNI                 string   `json:"sni"`
		ALPN                []string `json:"alpn"`
		Ciphers             []uint16 `json:"ciphers"`
		Extensions          []uint16 `json:"extensions"`
		SignatureAlgorithms []uint16 `json:"signature_algorithms"`
		ExpectedJA4         string   `json:"expected_ja4"`
	}
	var vectors struct {
		Vectors []labVector `json:"vectors"`
	}
	if err := json.NewDecoder(vf).Decode(&vectors); err != nil {
		t.Fatalf("decode ja4 vectors: %v", err)
	}
	byName := map[string]labVector{}
	for _, v := range vectors.Vectors {
		byName[v.Name] = v
	}
	curlV, okC := byName["curl-local"]
	if !okC {
		t.Fatal("curl-local vector missing from ja4_vectors.json")
	}
	chromeV, okB := byName["chrome-141"]
	if !okB {
		t.Fatal("chrome-141 vector missing from ja4_vectors.json")
	}

	mk := func(ip string, port uint16) *ingest.TxContext {
		m := ingest.NewTxManager()
		var k ingest.FlowKey
		k.SrcIP = netip.MustParseAddr(ip).As4()
		k.DstIP = netip.MustParseAddr("10.10.0.10").As4()
		k.SrcPort, k.DstPort, k.Family = port, 443, ingest.FamilyV4
		return m.NoteFlow(k)
	}

	curlTx = mk("192.0.2.23", 4411)
	var curlHV = &HeaderView{Method: fixture.ToolHeaders.Method, Version: "1.1", Headers: fixture.ToolHeaders.Headers}
	if err := AttachClientHello(curlTx, &ClientHelloSummary{
		Transport:           curlV.Transport[0],
		LegacyVersion:       curlV.LegacyVersion,
		SupportedVersions:   curlV.SupportedVersions,
		SNI:                 curlV.SNI,
		ALPN:                toBytesLists(curlV.ALPN),
		Ciphers:             curlV.Ciphers,
		Extensions:          curlV.Extensions,
		SignatureAlgorithms: curlV.SignatureAlgorithms,
	}); err != nil {
		t.Fatalf("attach curl hello: %v", err)
	}
	if err := AttachHeaderView(curlTx, curlHV); err != nil {
		t.Fatalf("attach curl headers: %v", err)
	}

	browserTx = mk("192.0.2.31", 52000)
	if err := AttachClientHello(browserTx, &ClientHelloSummary{
		Transport:           chromeV.Transport[0],
		LegacyVersion:       chromeV.LegacyVersion,
		SupportedVersions:   chromeV.SupportedVersions,
		SNI:                 chromeV.SNI,
		ALPN:                toBytesLists(chromeV.ALPN),
		Ciphers:             chromeV.Ciphers,
		Extensions:          chromeV.Extensions,
		SignatureAlgorithms: chromeV.SignatureAlgorithms,
	}); err != nil {
		t.Fatalf("attach browser hello: %v", err)
	}
	if err := AttachHeaderView(browserTx, &HeaderView{Method: fixture.BrowserHeaders.Method, Version: "1.1", Headers: fixture.BrowserHeaders.Headers}); err != nil {
		t.Fatalf("attach browser headers: %v", err)
	}
	return curlTx, browserTx
}

// TestDetectorWiring pins the ladder contract: Stage()=StageBots, Use()
// accepts it into the S5 slot, and a detached tx yields NO fragment.
func TestDetectorWiring(t *testing.T) {
	d := NewDetector()
	if d.Stage() != ladder.StageBots {
		t.Fatalf("Stage() = %v, want StageBots", d.Stage())
	}
	e := ladder.NewEngine()
	if err := e.Use(ladder.StageBots, d); err != nil {
		t.Fatalf("Use(S5): %v", err)
	}
	m := ingest.NewTxManager()
	var k ingest.FlowKey
	k.SrcIP = netip.MustParseAddr("192.0.2.9").As4()
	k.DstIP = netip.MustParseAddr("10.10.0.10").As4()
	k.SrcPort, k.DstPort, k.Family = 40000, 443, ingest.FamilyV4
	tx := m.NoteFlow(k)
	if v := e.EvaluateTx(tx); v == nil || v.Action != ladder.ActionAllow {
		t.Fatalf("detached tx must walk S5 silently (allow), got %+v", v)
	}
}

// TestLabPairDistinctVerdicts is THE acceptance: the curl-vs-browser pair
// produces DISTINCT ja4 verdicts (and distinct header fingerprints) in the
// rendered lab log.
func TestLabPairDistinctVerdicts(t *testing.T) {
	curlTx, browserTx := labPair(t)
	d := NewDetector()
	e := ladder.NewEngine()
	if err := e.Use(ladder.StageBots, d); err != nil {
		t.Fatalf("Use(S5): %v", err)
	}
	curlV := e.EvaluateTx(curlTx)
	browserV := e.EvaluateTx(browserTx)
	if curlV == nil || browserV == nil {
		t.Fatal("attached txes must produce verdicts")
	}
	curlLog, browserLog := LabLogLine(curlTx), LabLogLine(browserTx)
	if curlLog == "" || browserLog == "" {
		t.Fatal("lab-log lines must render for both txes")
	}

	ja4 := func(log string) string {
		for _, f := range strings.Fields(log) {
			if strings.HasPrefix(f, "ja4=") {
				return strings.TrimPrefix(f, "ja4=")
			}
		}
		return ""
	}
	curlJA4, browserJA4 := ja4(curlLog), ja4(browserLog)
	if curlJA4 == "" || browserJA4 == "" {
		t.Fatalf("lab-log lines must carry ja4=: %q / %q", curlLog, browserLog)
	}
	if curlJA4 == browserJA4 {
		t.Fatalf("acceptance violated: curl and browser carry the SAME ja4 (%q)", curlJA4)
	}
	if curlJA4 != "t13d4907h2_0d8feac7bc37_7395dae3b2f3" {
		t.Errorf("curl tx ja4 = %q, want the golden curl vector", curlJA4)
	}
	if browserJA4 != "t13d1517h2_8daaf6152771_dcad5a053991" {
		t.Errorf("browser tx ja4 = %q, want the golden chrome-141 vector", browserJA4)
	}
	hf := func(log string) string {
		for _, f := range strings.Fields(log) {
			if strings.HasPrefix(f, "hf=") {
				return strings.TrimPrefix(f, "hf=")
			}
		}
		return ""
	}
	if hf(curlLog) == "" || hf(curlLog) == hf(browserLog) {
		t.Fatalf("header fingerprints must be present and distinct: %q / %q", curlLog, browserLog)
	}
	// verdict vocabulary: v0 verdicts are log-tier fragments folded through
	// the ladder (log outranks pass; never block/allow at S5).
	if curlV.Action != ladder.ActionLog {
		t.Errorf("curl verdict action = %q, want log (v0 S5 is log-tier)", curlV.Action)
	}
	if !containsRule(curlV.Rules, "bot:headers") || !containsRule(curlV.Rules, "bot:ja4") {
		t.Errorf("curl verdict rules = %v, want both detector evidence ids", curlV.Rules)
	}
	if browserV.Action != ladder.ActionLog {
		t.Errorf("browser verdict action = %q, want log", browserV.Action)
	}
	if containsRule(browserV.Rules, "bot:headers") {
		t.Errorf("browser verdict rules = %v; the browser shape must NOT carry the tool header evidence", browserV.Rules)
	}
	// JA4-only evidence still scores: the browser tx logs bot:ja4 with a
	// smaller score than the double-tool curl tx.
	if curlV.Score <= browserV.Score {
		t.Errorf("curl score %d must exceed browser score %d (both planes vs one prior)", curlV.Score, browserV.Score)
	}
}

func containsRule(rules []ladder.RuleID, id string) bool {
	for _, r := range rules {
		if string(r) == id {
			return true
		}
	}
	return false
}

// TestLabLogGolden pins the rendered lab-log FORMAT against the expected
// pair (testdata/lab_log_expected.json): the fixture txes walk the wired
// S5 detector (the lab run), then the rendered lines compare byte-for-byte
// against the expected artifact — same field order, same values.
func TestLabLogGolden(t *testing.T) {
	curlTx, browserTx := labPair(t)
	d := NewDetector()
	e := ladder.NewEngine()
	if err := e.Use(ladder.StageBots, d); err != nil {
		t.Fatalf("Use(S5): %v", err)
	}
	e.EvaluateTx(curlTx)
	e.EvaluateTx(browserTx)
	curlLog, browserLog := LabLogLine(curlTx), LabLogLine(browserTx)

	f, err := os.Open("testdata/lab_log_expected.json")
	if err != nil {
		t.Fatalf("open expected lab log: %v", err)
	}
	defer f.Close()
	var expected struct {
		Lines []string `json:"lines"`
	}
	if err := json.NewDecoder(f).Decode(&expected); err != nil {
		t.Fatalf("decode expected lab log: %v", err)
	}
	if len(expected.Lines) != 2 {
		t.Fatalf("expected lab log must carry exactly 2 lines, got %d", len(expected.Lines))
	}
	if curlLog != expected.Lines[0] {
		t.Errorf("curl lab line drift:\n got %q\nwant %q", curlLog, expected.Lines[0])
	}
	if browserLog != expected.Lines[1] {
		t.Errorf("browser lab line drift:\n got %q\nwant %q", browserLog, expected.Lines[1])
	}
}

// TestAttachRoundTrip pins the tx attachment contract (the TR-29 supply
// surface, same pattern as ladder.AttachView).
func TestAttachRoundTrip(t *testing.T) {
	m := ingest.NewTxManager()
	var k ingest.FlowKey
	k.SrcIP = netip.MustParseAddr("192.0.2.77").As4()
	k.Family = ingest.FamilyV4
	tx := m.NoteFlow(k)

	if ClientHelloOf(tx) != nil || HeaderViewOf(tx) != nil {
		t.Fatal("detached tx must read nil for both planes")
	}
	ch := &ClientHelloSummary{Transport: 't', LegacyVersion: 771, Ciphers: []uint16{4865}}
	if err := AttachClientHello(tx, ch); err != nil {
		t.Fatalf("AttachClientHello: %v", err)
	}
	got := ClientHelloOf(tx)
	if got == nil || got.Transport != 't' || len(got.Ciphers) != 1 || got.Ciphers[0] != 4865 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	hv := &HeaderView{Method: "GET", Version: "1.1", Headers: [][2]string{{"Host", "x"}}}
	if err := AttachHeaderView(tx, hv); err != nil {
		t.Fatalf("AttachHeaderView: %v", err)
	}
	if hv2 := HeaderViewOf(tx); hv2 == nil || hv2.Method != "GET" || len(hv2.Headers) != 1 {
		t.Errorf("HeaderView round-trip mismatch: %+v", hv2)
	}
}
