package botdef

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// goldenJA4 loads the FoxIO golden vectors (testdata/ja4_vectors.json) and
// drives ja4f end to end: typed uint16 lists in (wire order for ALPN,
// arbitrary order for ciphers/extensions), JA4/JA4_r/JA4_o/JA4_ro strings
// out — every vector traceable to a published FoxIO raw string (sources in
// the file's note field).
func TestJA4GoldenVectors(t *testing.T) {
	f, err := os.Open("testdata/ja4_vectors.json")
	if err != nil {
		t.Fatalf("open vectors: %v", err)
	}
	defer f.Close()
	var fixture struct {
		Vectors []struct {
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
			ExpectedJA4R        string   `json:"expected_ja4_r"`
		} `json:"vectors"`
	}
	if err := json.NewDecoder(f).Decode(&fixture); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(fixture.Vectors) < 4 {
		t.Fatalf("expected at least 4 golden vectors, got %d", len(fixture.Vectors))
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ch := &ClientHelloSummary{
				Transport:           v.Transport[0],
				LegacyVersion:       v.LegacyVersion,
				SupportedVersions:   v.SupportedVersions,
				SNI:                 v.SNI,
				ALPN:                toBytesLists(v.ALPN),
				Ciphers:             v.Ciphers,
				Extensions:          v.Extensions,
				SignatureAlgorithms: v.SignatureAlgorithms,
			}
			got := ja4f(ch)
			if got.JA4 != v.ExpectedJA4 {
				t.Errorf("JA4 mismatch:\n got %q\nwant %q", got.JA4, v.ExpectedJA4)
			}
			if got.JA4R != v.ExpectedJA4R {
				t.Errorf("JA4_r mismatch:\n got %q\nwant %q", got.JA4R, v.ExpectedJA4R)
			}
		})
	}
}

// TestJA4HashVariants pins the -o (original-order) hashes for the foxio
// spec example (published JA4_o/JA4_ro on the JA4.md worked example) and
// the o/ro structural equality (same header, different hash body) on the
// remaining vectors.
func TestJA4HashVariants(t *testing.T) {
	f, err := os.Open("testdata/ja4_vectors.json")
	if err != nil {
		t.Fatalf("open vectors: %v", err)
	}
	defer f.Close()
	var fixture struct {
		Vectors []struct {
			Name                string   `json:"name"`
			Transport           string   `json:"transport"`
			LegacyVersion       uint16   `json:"legacy_version"`
			SupportedVersions   []uint16 `json:"supported_versions"`
			SNI                 string   `json:"sni"`
			ALPN                []string `json:"alpn"`
			Ciphers             []uint16 `json:"ciphers"`
			Extensions          []uint16 `json:"extensions"`
			SignatureAlgorithms []uint16 `json:"signature_algorithms"`
			ExpectedJA4O        string   `json:"expected_ja4_o"`
			ExpectedJA4RO       string   `json:"expected_ja4_ro"`
		} `json:"vectors"`
	}
	if err := json.NewDecoder(f).Decode(&fixture); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ch := &ClientHelloSummary{
				Transport:           v.Transport[0],
				LegacyVersion:       v.LegacyVersion,
				SupportedVersions:   v.SupportedVersions,
				SNI:                 v.SNI,
				ALPN:                toBytesLists(v.ALPN),
				Ciphers:             v.Ciphers,
				Extensions:          v.Extensions,
				SignatureAlgorithms: v.SignatureAlgorithms,
			}
			got := ja4f(ch)
			if v.ExpectedJA4O != "" && got.JA4O != v.ExpectedJA4O {
				t.Errorf("JA4_o mismatch:\n got %q\nwant %q", got.JA4O, v.ExpectedJA4O)
			}
			if v.ExpectedJA4O == "" {
				t.Errorf("vector %q is missing its expected_ja4_o pin (every golden vector must pin the -o variant)", v.Name)
			}
			if v.ExpectedJA4RO == "" {
				t.Errorf("vector %q is missing its expected_ja4_ro pin", v.Name)
			}
			// structural: o-variant shares the a-section with JA4.
			if len(got.JA4) > 10 && len(got.JA4O) > 10 && got.JA4[:10] != got.JA4O[:10] {
				t.Errorf("JA4_o a-section drift: %q vs %q", got.JA4[:10], got.JA4O[:10])
			}
		})
	}
}

// TestJA4ALPNCodes drives the spec's ALPN edge cases (testdata table) —
// the a-section code derived from the first ALPN value, including the
// hex-fallback rule for non-ASCII-alphanumeric bytes.
func TestJA4ALPNCodes(t *testing.T) {
	f, err := os.Open("testdata/ja4_vectors.json")
	if err != nil {
		t.Fatalf("open vectors: %v", err)
	}
	defer f.Close()
	var fixture struct {
		ALPNCases []struct {
			Cases []struct {
				Values []string `json:"values"`
				Want   string   `json:"want"`
			} `json:"cases"`
			Note string `json:"note"`
		} `json:"alpn_cases"`
	}
	if err := json.NewDecoder(f).Decode(&fixture); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(fixture.ALPNCases) == 0 || len(fixture.ALPNCases[0].Cases) == 0 {
		t.Fatal("empty alpn_cases table")
	}
	for i, c := range fixture.ALPNCases[0].Cases {
		t.Run(fmt.Sprintf("case%02d", i), func(t *testing.T) {
			ch := &ClientHelloSummary{Transport: 't', ALPN: toBytesLists(c.Values)}
			got := ja4f(ch).ALPNCode
			if got != c.Want {
				t.Errorf("ALPN code for %q: got %q, want %q", c.Values, got, c.Want)
			}
		})
	}
}

// TestJA4SelfConsistency is the v0 bar for inputs WITHOUT a published
// vector: same input → same JA4; any difference in the hashed surface →
// different JA4 (the spec-defined string format is structural). The base
// carries every field so each mutation removes/replaces real hashed
// content (a mod on an empty field would be vacuous).
func TestJA4SelfConsistency(t *testing.T) {
	base := &ClientHelloSummary{
		Transport:           't',
		LegacyVersion:       771,
		SupportedVersions:   []uint16{772, 771},
		SNI:                 "x.test",
		ALPN:                [][]byte{[]byte("h2")},
		Ciphers:             []uint16{4865, 4866},
		Extensions:          []uint16{5, 11},
		SignatureAlgorithms: []uint16{1027, 1537},
	}
	same := &ClientHelloSummary{
		Transport:           't',
		LegacyVersion:       771,
		SupportedVersions:   []uint16{772, 771},
		SNI:                 "x.test",
		ALPN:                [][]byte{[]byte("h2")},
		Ciphers:             []uint16{4865, 4866},
		Extensions:          []uint16{5, 11},
		SignatureAlgorithms: []uint16{1027, 1537},
	}
	if ja4f(base).JA4 != ja4f(same).JA4 {
		t.Fatal("identical ClientHello summaries must produce identical JA4 strings")
	}
	mods := map[string]func(*ClientHelloSummary){
		"ciphers":      func(c *ClientHelloSummary) { c.Ciphers = []uint16{4865, 4867} },
		"alpn":         func(c *ClientHelloSummary) { c.ALPN = [][]byte{[]byte("http/1.1")} },
		"sni":          func(c *ClientHelloSummary) { c.SNI = "" },
		"ciphern":      func(c *ClientHelloSummary) { c.Ciphers = append(c.Ciphers, 49195) },
		"extn":         func(c *ClientHelloSummary) { c.Extensions = append(c.Extensions, 65281) },
		"sigalgs":      func(c *ClientHelloSummary) { c.SignatureAlgorithms = []uint16{1027, 1283} },
		"supportedver": func(c *ClientHelloSummary) { c.SupportedVersions = []uint16{771} },
		"transport":    func(c *ClientHelloSummary) { c.Transport = 'q' },
	}
	for name, mod := range mods {
		alt := &ClientHelloSummary{
			Transport:           't',
			LegacyVersion:       771,
			SupportedVersions:   []uint16{772, 771},
			SNI:                 "x.test",
			ALPN:                [][]byte{[]byte("h2")},
			Ciphers:             []uint16{4865, 4866},
			Extensions:          []uint16{5, 11},
			SignatureAlgorithms: []uint16{1027, 1537},
		}
		mod(alt)
		if ja4f(alt).JA4 == ja4f(base).JA4 {
			t.Errorf("modifying %s must change the JA4 string", name)
		}
	}
}

// toBytesLists converts JSON string values into the ALPN [][]byte shape.
func toBytesLists(vals []string) [][]byte {
	out := make([][]byte, len(vals))
	for i, v := range vals {
		out[i] = []byte(v)
	}
	return out
}
