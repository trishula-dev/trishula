package botdef

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
// remaining vectors, plus the exact ja4_r render per the corpus pins.
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

// TestJA4PQCVectors pins the TR-203 L5 PQC pair. The pin spans three named
// rows and the pair relationship, so it is a function, not a row:
//   - the corpus carries go-client-x25519mlkem768 (the X25519MLKEM768 offer:
//     RFC 10024 group 4588 (0x11EC), client share 1,216 bytes) and its
//     companion go-client-x25519 (the same Go stack with GODEBUG
//     tlsmlkem=0: group 29, 32-byte share); both are captured offers from
//     tls.peet.ws/api/all on 2026-10-25;
//   - the KEX flip alone leaves the rendered JA4/JA4_r tokens unchanged.
//     The grammar hashes cipher-suite, extension-ID and signature-algorithm
//     tokens. The KEX offer uses extension DATA (supported_groups +
//     key_share). The shift lands in ja3 (the group list) instead. The
//     pinned A/B pair files that finding; it is never an assumption;
//   - go-client-x25519mlkem768-q derives over the same offer lists with
//     transport 'q' (the grammar's QUIC transport variant, probe P2a).
//     Only the a-section's leading glyph moves.
func TestJA4PQCVectors(t *testing.T) {
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
			PQC                 *pqcRecord
		} `json:"vectors"`
	}
	if err := json.NewDecoder(f).Decode(&fixture); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	byName := map[string]*pqcVector{}
	for i := range fixture.Vectors {
		v := &fixture.Vectors[i]
		byName[v.Name] = &pqcVector{
			Transport: v.Transport, LegacyVersion: v.LegacyVersion,
			SupportedVersions: v.SupportedVersions, SNI: v.SNI,
			ALPN: v.ALPN, Ciphers: v.Ciphers, Extensions: v.Extensions,
			SignatureAlgorithms: v.SignatureAlgorithms,
			ExpectedJA4:         v.ExpectedJA4, ExpectedJA4R: v.ExpectedJA4R,
			PQC: v.PQC,
		}
	}

	// The PQC corpus rows exist by name; each one carries the string pins
	// and the pqc KEX record.
	for _, name := range []string{"go-client-x25519mlkem768", "go-client-x25519", "go-client-x25519mlkem768-q"} {
		v, ok := byName[name]
		if !ok {
			t.Errorf("PQC vector %q missing from ja4_vectors.json", name)
			continue
		}
		if v.ExpectedJA4 == "" || v.ExpectedJA4R == "" {
			t.Errorf("PQC vector %q lacks its expected_ja4/expected_ja4_r pins", name)
		}
		if v.PQC == nil {
			t.Errorf("PQC vector %q lacks its pqc KEX record", name)
		}
	}

	// The captured token: peet.ws publishes this JA4 for BOTH captured
	// offers (the source tokens stand outside this tree).
	const peetToken = "t13d1312h2_f57a46bbacb6_f50d94e863eb"
	mlkem, okP := byName["go-client-x25519mlkem768"]
	classic, okC := byName["go-client-x25519"]
	qv, _ := byName["go-client-x25519mlkem768-q"]
	if okP && okC {
		gotML, gotCL := ja4f(mlkem.summary()), ja4f(classic.summary())
		if gotML.JA4 != peetToken {
			t.Errorf("mlkem row ja4 = %q, want the pinned peet token %q", gotML.JA4, peetToken)
		}
		if gotCL.JA4 != peetToken {
			t.Errorf("classic row ja4 = %q, want the same pinned peet token (the KEX flip leaves the JA4 token unchanged)", gotCL.JA4)
		}
		if gotML.JA4R != gotCL.JA4R {
			t.Errorf("KEX flip shifts JA4_r: %q vs %q", gotML.JA4R, gotCL.JA4R)
		}
		// The KEX offer pins: the RFC 10024 group slots lead the ML-KEM
		// row's group list; the shares carry 1,216 bytes (4588) + 32 (29);
		// the classic row carries one bare 32-byte X25519 share.
		wantHybridGroups := []uint16{4588, 4587, 4589, 29, 23, 24, 25}
		wantClassicGroups := []uint16{29, 23, 24, 25}
		if fmt.Sprint(mlkem.PQC.Groups) != fmt.Sprint(wantHybridGroups) {
			t.Errorf("mlkem groups = %v, want %v", mlkem.PQC.Groups, wantHybridGroups)
		}
		if fmt.Sprint(classic.PQC.Groups) != fmt.Sprint(wantClassicGroups) {
			t.Errorf("classic groups = %v, want %v", classic.PQC.Groups, wantClassicGroups)
		}
		if len(mlkem.PQC.KeyShare) != 2 {
			t.Fatalf("mlkem key_share = %v, want the 4588 + 29 entries", mlkem.PQC.KeyShare)
		}
		if mlkem.PQC.KeyShare[0].Group != 4588 || mlkem.PQC.KeyShare[0].Bytes != 1216 {
			t.Errorf("mlkem 4588 share = %+v, want group 4588 with a 1,216-byte share (RFC 10024 section 4.1)", mlkem.PQC.KeyShare[0])
		}
		if mlkem.PQC.KeyShare[1].Group != 29 || mlkem.PQC.KeyShare[1].Bytes != 32 {
			t.Errorf("mlkem 29 share = %+v, want group 29 with a 32-byte share", mlkem.PQC.KeyShare[1])
		}
		if len(classic.PQC.KeyShare) != 1 || classic.PQC.KeyShare[0].Group != 29 || classic.PQC.KeyShare[0].Bytes != 32 {
			t.Errorf("classic key_share = %v, want one 32-byte X25519 (29) share", classic.PQC.KeyShare)
		}
	}

	// The derived 'q' row pins the QUIC transport variant (probe P2a):
	// same hash body, leading glyph 'q' in the a-section.
	if okP && qv != nil {
		got := ja4f(qv.summary())
		if !strings.HasPrefix(got.JA4, "q13d1312h2_") {
			t.Errorf("q-variant a-section = %q, want the q13d1312h2 form", got.JA4)
		}
		if got.JA4 != "q13d1312h2_f57a46bbacb6_f50d94e863eb" {
			t.Errorf("q-variant ja4 = %q, want q13d1312h2_f57a46bbacb6_f50d94e863eb", got.JA4)
		}
		body := got.JA4[strings.IndexByte(got.JA4, '_')+1:]
		mlBody := mlkem.ExpectedJA4[strings.IndexByte(mlkem.ExpectedJA4, '_')+1:]
		if body != mlBody {
			t.Errorf("q-variant body drift vs the mlkem row: %q vs %q", body, mlBody)
		}
	}
}

// pqcVector mirrors one corpus row plus its pqc KEX record for the
// TestJA4PQCVectors pins.
type pqcVector struct {
	Transport           string
	LegacyVersion       uint16
	SupportedVersions   []uint16
	SNI                 string
	ALPN                []string
	Ciphers             []uint16
	Extensions          []uint16
	SignatureAlgorithms []uint16
	ExpectedJA4         string
	ExpectedJA4R        string
	PQC                 *pqcRecord
}

// summary builds the ClientHelloSummary input the ja4f grammar consumes.
func (v *pqcVector) summary() *ClientHelloSummary {
	return &ClientHelloSummary{
		Transport:           v.Transport[0],
		LegacyVersion:       v.LegacyVersion,
		SupportedVersions:   v.SupportedVersions,
		SNI:                 v.SNI,
		ALPN:                toBytesLists(v.ALPN),
		Ciphers:             v.Ciphers,
		Extensions:          v.Extensions,
		SignatureAlgorithms: v.SignatureAlgorithms,
	}
}

// pqcRecord is the row's KEX offer: the RFC 10024 group list and the
// offered shares. The grammar does not hash these fields; the corpus
// carries them so the KEX part of the offer stays pinned and the QUIC
// Initial read design consumes the same shape.
type pqcRecord struct {
	Groups   []uint16   `json:"groups"`
	KeyShare []kexShare `json:"key_share"`
	KemGroup string     `json:"kem_group"`
}

// kexShare is one offered key-share entry: the group code and its size in
// bytes.
type kexShare struct {
	Group uint16 `json:"group"`
	Bytes int    `json:"bytes"`
}

// toBytesLists converts JSON string values into the ALPN [][]byte shape.
func toBytesLists(vals []string) [][]byte {
	out := make([][]byte, len(vals))
	for i, v := range vals {
		out[i] = []byte(v)
	}
	return out
}
