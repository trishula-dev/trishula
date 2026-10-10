package botdef

import (
	"encoding/json"
	"os"
	"testing"
)

// loadHeaderPair loads the curl-vs-browser §11.3 header-plane pair
// (testdata/curl_vs_browser.json).
func loadHeaderPair(t *testing.T) (browser, tool *HeaderView) {
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
	browser = &HeaderView{
		Method:  fixture.BrowserHeaders.Method,
		Version: "1.1",
		Headers: fixture.BrowserHeaders.Headers,
	}
	tool = &HeaderView{
		Method:  fixture.ToolHeaders.Method,
		Version: "1.1",
		Headers: fixture.ToolHeaders.Headers,
	}
	return browser, tool
}

func lookup(hv *HeaderView, name string) string {
	if hv.Values == nil {
		hv.Values = map[string]string{}
		for _, kv := range hv.Headers {
			hv.Values[lower(kv[0])] = kv[1]
		}
	}
	return hv.Values[name]
}

// TestHeaderFingerprintBrowserShape pins the classification evidence on the
// browser fixture: browser-ish, not tool-ish, UA + AL + sec-ch all seen,
// canonical h1 casing, and the presence bits for the browser header set.
func TestHeaderFingerprintBrowserShape(t *testing.T) {
	browser, tool := loadHeaderPair(t)
	_ = tool
	fp := headerFingerprint(browser)
	if !fp.Browserish {
		t.Errorf("browser fixture must classify browser-ish (reasons=%v)", fp.Reasons)
	}
	if fp.Toolish {
		t.Errorf("browser fixture must not classify tool-ish (reasons=%v)", fp.Reasons)
	}
	if ua := lookup(browser, "user-agent"); fp.UserAgent != ua || !fp.HasUA {
		t.Errorf("UserAgent=%q HasUA=%v, want %q true", fp.UserAgent, fp.HasUA, ua)
	}
	if !fp.HasAL {
		t.Error("browser fixture carries accept-language; HasAL must be true")
	}
	if !fp.HasSecCH {
		t.Error("browser fixture carries sec-ch-ua hints; HasSecCH must be true")
	}
	if fp.Casing != "canonical" {
		t.Errorf("browser fixture is sent-capitalized; Casing=%q want canonical", fp.Casing)
	}
	if len(fp.Order) != len(browser.Headers) {
		t.Errorf("Order length %d != fixture header count %d", len(fp.Order), len(browser.Headers))
	}
	want, got := fp.Hash, headerFingerprint(browser).Hash
	if want != got {
		t.Errorf("fingerprint not deterministic: %q vs %q", want, got)
	}
}

// TestHeaderFingerprintToolShape pins the tool classification on the curl
// fixture and the casing signal: an all-lowercase re-send of the same
// logical headers must classify NOT-canonical AND must hash differently
// from the capitalized send (casing is evidence on the h1 wire).
func TestHeaderFingerprintToolShape(t *testing.T) {
	browser, tool := loadHeaderPair(t)
	_ = browser
	fp := headerFingerprint(tool)
	if !fp.Toolish {
		t.Errorf("curl fixture must classify tool-ish (reasons=%v)", fp.Reasons)
	}
	if fp.Browserish {
		t.Errorf("curl fixture must not classify browser-ish (reasons=%v)", fp.Reasons)
	}
	if ua := lookup(tool, "user-agent"); fp.UserAgent != ua || !fp.HasUA {
		t.Errorf("UserAgent=%q HasUA=%v, want %q true", fp.UserAgent, fp.HasUA, ua)
	}
	if fp.HasAL {
		t.Error("curl fixture carries no accept-language; HasAL must be false")
	}
	if fp.HasSecCH {
		t.Error("curl fixture carries no sec-ch hints; HasSecCH must be false")
	}

	// casing: lowercase the same logical headers → different hash + lower casing
	lowered := &HeaderView{Method: tool.Method, Version: tool.Version}
	for _, kv := range tool.Headers {
		lowered.Headers = append(lowered.Headers, [2]string{lower(kv[0]), kv[1]})
	}
	fpLower := headerFingerprint(lowered)
	if fpLower.Casing != "lower" {
		t.Errorf("lowercased re-send: Casing=%q want lower", fpLower.Casing)
	}
	if fpLower.Hash == fp.Hash {
		t.Error("casing change must change the header fingerprint (h1 casing is evidence)")
	}
	// order swap: same headers, different order → different hash
	swapped := &HeaderView{Method: tool.Method, Version: tool.Version}
	for i := len(tool.Headers) - 1; i >= 0; i-- {
		swapped.Headers = append(swapped.Headers, tool.Headers[i])
	}
	fpSwap := headerFingerprint(swapped)
	if fpSwap.Hash == fp.Hash {
		t.Error("header-order change must change the header fingerprint (order is evidence)")
	}
}

// TestHeaderPairDistinct is the header half of the TR-12 acceptance: the
// curl-vs-browser pair produces DISTINCT header fingerprints AND distinct
// classifications (tool vs browser).
func TestHeaderPairDistinct(t *testing.T) {
	browser, tool := loadHeaderPair(t)
	fb, ft := headerFingerprint(browser), headerFingerprint(tool)
	if fb.Hash == ft.Hash {
		t.Fatal("curl-vs-browser pair must produce distinct header fingerprints")
	}
	if ft.Toolish == fb.Toolish || ft.Browserish == fb.Browserish {
		t.Fatalf("classifications must differ: browser(toolid=%v brows=%v) tool(toolid=%v brows=%v)",
			fb.Toolish, fb.Browserish, ft.Toolish, ft.Browserish)
	}
}

// TestHeaderEmptyView pins the degenerate input: an empty header view is a
// fingerprint (hash of nothing) that classifies tool-ish, not a panic and
// not "browser".
func TestHeaderEmptyView(t *testing.T) {
	fp := headerFingerprint(&HeaderView{Method: "GET", Version: "1.1"})
	if !fp.Toolish || fp.Browserish {
		t.Errorf("empty view must classify tool-ish (reasons=%v)", fp.Reasons)
	}
	if fp.Hash == "" {
		t.Error("empty view still produces a stable fingerprint hash")
	}
}
