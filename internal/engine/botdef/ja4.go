// Package botdef implements the §12 bot-detector family v0: JA4 TLS client
// fingerprinting (terminated-hop ClientHello summary in, FoxIO JA4 string
// out) and the h1-style header-plane fingerprint (ordered normalized
// header-name vector + presence vector + casing/UA/AL evidence, stable hash
// + tool-vs-browser classification), glued to the ladder as §19.1 S5
// StageBots evaluators over the ingest transaction context.
//
// TR-12 v0 SLICE BOUNDARIES (deliberate):
//
//   - No TLS parsing happens here. TR-15 (TLS handshake planes) owns the
//     ClientHello → ClientHelloSummary extraction; TR-29 the kernel-side
//     capture. The ingest path MUST supply the summary below; until then
//     the ladder's S5 stage sees no fragment (never a fabricated verdict).
//   - No fingerprint "known-tooling DB" matching (FoxIO's JA4+ database is
//     a separate digest-pinned feed per PRD §12.3): v0 emits verdicts on
//     the computed fingerprints + header-plane contradiction evidence.
//   - JA4H (FoxIO's HTTP client fingerprint) is deliberately NOT claimed:
//     FoxIO's published JA4H hash vectors lack reconstructible inputs
//     (technical_details/JA4H.md is an unpublished stub). v0 computes the
//     header fingerprint below and leaves the JA4H hash as TR-19 work.
//
// All of the below is FoxIO JA4+ surface; JA4 itself is BSD-3-Clause, the
// JA4+ family FoxIO License 1.1 (README.md, FoxIO-LLC/ja4). This package
// IMPLEMENTS the JA4 string assembly per the 2023 spec; it does not copy
// FoxIO source.
package botdef

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ClientHelloSummary is the input contract for JA4Fingerprint: exactly what
// the §11.3 view's TLS scope can supply per a terminated hop. The extract
// side (TR-15/29: kernel capture → userspace extract) owes:
//
//   - Transport: 't' (TLS over TCP), 'q' (QUIC Initial), 'd' (DTLS).
//   - LegacyVersion + SupportedVersions as the wire carries them (uint16s).
//   - SNI as decoded by the extract (empty = no SNI extension).
//   - ALPN: the protocol-name list in offer order (first value rules the
//     a-section code; values outside UTF-8 must still round-trip their
//     bytes here — the ALPN code path hex-falls-back per spec).
//   - Ciphers, Extensions, SignatureAlgorithms: the raw uint16 lists in
//     offer order (JA4 re-sorts internally); GREASE values are welcome in
//     (the spec filter is internal) but an extract MAY pre-filter — the
//     counts/hashes are computed post-GREASE either way.
//
// This struct intentionally mirrors a parsed ClientHello (version + ALPN +
// ciphers + extensions as numeric lists) and NOT a byte slice: TR-04's
// FlowEvent carries flow metadata only, so the byte-level supply arrives
// with TR-15's hello reassembly. Until an ingest hop attaches a summary
// (AttachClientHello), S5 emits no fragment.
type ClientHelloSummary struct {
	Transport           byte // 't' | 'q' | 'd'
	LegacyVersion       uint16
	SupportedVersions   []uint16 // supported_versions extension values, wire order
	SNI                 string
	ALPN                [][]byte // first value rules; UTF-8 bytes as offered
	Ciphers             []uint16
	Extensions          []uint16
	SignatureAlgorithms []uint16
}

// ja4Result is the full JA4 render: the canonical string plus the raw
// variants (debug/diff surface; not part of the v0 verdict).
type ja4Result struct {
	JA4      string // t13d1516h2_8daaf6152771_e5627efa2ab1
	JA4R     string // raw, sorted lists
	JA4O     string // hash-of-original-order variant
	JA4RO    string // raw, original order
	Version  string // resolved version code ("13", "12", …)
	CipherN  int
	ExtN     int
	ALPNCode string
}

// ja4GREASETable is the GREASE value set (draft-davidben-tls-grease-01):
// xAxA patterns in both cipher and extension space. The JA4 spec counts and
// hashes post-GREASE-filter.
var ja4GREASETable = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true, 0x4a4a: true,
	0x5a5a: true, 0x6a6a: true, 0x7a7a: true, 0x8a8a: true, 0x9a9a: true,
	0xaaaa: true, 0xbaba: true, 0xcaca: true, 0xdada: true, 0xeaea: true,
	0xfafa: true,
}

// ja4TLSVersions maps the protocol-version uint16 to its 2-char JA4 code
// (JA4.md "TLS and DTLS Version"; DTLS 'd' codes land with DTLS support —
// a 'd' transport with an unmapped value codes "00").
var ja4TLSVersions = map[uint16]string{
	0x0002: "s2",
	0x0300: "s3",
	0x0301: "10",
	0x0302: "11",
	0x0303: "12",
	0x0304: "13",
	0xfefc: "d3",
	0xfefd: "d2",
	0xfeff: "d1",
}

// ja4f computes the full JA4 render per the FoxIO JA4 spec (2023). All
// hash strings are lower-case (hex.EncodeToString lower-cases); everything
// is value-derived for determinism — slice order enters only through
// documented sort/offer-order paths, never map iteration.
func ja4f(ch *ClientHelloSummary) ja4Result {
	trans := ch.Transport
	if trans != 't' && trans != 'q' && trans != 'd' {
		trans = 't' // malformed transport falls to TCP, never a fabricated 'q'
	}

	// --- version: supported_versions' max non-GREASE wins when present;
	// otherwise the legacy ProtocolVersion; unknown = "00".
	verCode := "00"
	if len(ch.SupportedVersions) > 0 {
		max := uint16(0)
		for _, sv := range ch.SupportedVersions {
			if ja4GREASETable[sv] {
				continue
			}
			if sv > max {
				max = sv
			}
		}
		if max != 0 {
			verCode = ja4TLSVersions[max]
		}
	} else {
		verCode = ja4TLSVersions[ch.LegacyVersion]
	}
	if verCode == "" {
		verCode = "00"
	}

	sniFlag := 'i'
	if ch.SNI != "" {
		sniFlag = 'd'
	}

	// --- ciphers: GREASE-filtered (kept: SCSV 0x00ff/0x5600 and the
	// experimental 0xfe00-0xfeff range — only the xAxA GREASE table is
	// dropped), hex-sorted for the canonical hash.
	cipherHex := make([]string, 0, len(ch.Ciphers))
	for _, c := range ch.Ciphers {
		if ja4GREASETable[c] {
			continue
		}
		cipherHex = append(cipherHex, fmt.Sprintf("%04x", c))
	}
	cipherCount := len(cipherHex)
	if cipherCount > 99 {
		cipherCount = 99
	}
	cipherHexSorted := append([]string(nil), cipherHex...)
	sort.Strings(cipherHexSorted)
	sortedCiphers := strings.Join(cipherHexSorted, ",")

	// --- extensions: GREASE-filtered, counted (SNI/ALPN included here);
	// the HASH-SORTED scope drops SNI (0000) and ALPN (0010) as they are
	// already captured in the a-section.
	extHex := make([]string, 0, len(ch.Extensions))
	extHexHashScope := make([]string, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if ja4GREASETable[e] {
			continue
		}
		h := fmt.Sprintf("%04x", e)
		extHex = append(extHex, h)
		if e != 0x0000 && e != 0x0010 {
			extHexHashScope = append(extHexHashScope, h)
		}
	}
	extCount := len(extHex)
	if extCount > 99 {
		extCount = 99
	}
	extOriginal := append([]string(nil), extHex...) // offer order (post-GREASE)
	sort.Strings(extHexHashScope)
	sortedExts := strings.Join(extHexHashScope, ",")

	// --- signature algorithms: GREASE-filtered, OFFER ORDER (never sorted);
	// underscore-joined to the extension list when present.
	sigHex := make([]string, 0, len(ch.SignatureAlgorithms))
	for _, s := range ch.SignatureAlgorithms {
		if ja4GREASETable[s] {
			continue
		}
		sigHex = append(sigHex, fmt.Sprintf("%04x", s))
	}
	sortedExtStr := sortedExts
	originalExtStr := strings.Join(extOriginal, ",")
	if len(sigHex) > 0 {
		sortedExtStr = sortedExts + "_" + strings.Join(sigHex, ",")
		originalExtStr = originalExtStr + "_" + strings.Join(sigHex, ",")
	}

	a := string(trans) + verCode + string(sniFlag) +
		fmt.Sprintf("%02d%02d", cipherCount, extCount) +
		ja4ALPNCode(ch.ALPN)

	// --- hash bodies; empty lists hash to a zeros marker, never sha256("").
	cipherHash := ja4SHA12(sortedCiphers)
	if len(ch.Ciphers) == 0 {
		cipherHash = emptyHashMarker
	}
	extHash := ja4SHA12(sortedExtStr)
	origExtHash := ja4SHA12(originalExtStr)
	if len(extHexHashScope) == 0 {
		extHash = emptyHashMarker
	}
	if len(extOriginal) == 0 {
		origExtHash = emptyHashMarker
	}
	// The o-variant's cipher body hashes the original (offer) order.
	origCipherHash := ja4SHA12(strings.Join(cipherHex, ","))
	if len(ch.Ciphers) == 0 {
		origCipherHash = emptyHashMarker
	}

	return ja4Result{
		JA4:      a + "_" + cipherHash + "_" + extHash,
		JA4R:     a + "_" + sortedCiphers + "_" + sortedExtStr,
		JA4O:     a + "_" + origCipherHash + "_" + origExtHash,
		JA4RO:    a + "_" + strings.Join(cipherHex, ",") + "_" + originalExtStr,
		Version:  verCode,
		CipherN:  cipherCount,
		ExtN:     extCount,
		ALPNCode: ja4ALPNCode(ch.ALPN),
	}
}

// emptyHashMarker is JA4's empty-field hash token: a zeros 12-char marker
// instead of a hash of nothing, so an empty field is legible to the user.
const emptyHashMarker = "000000000000"

// ja4SHA12 is the JA4 hash: sha256 (lower-case hex), truncated to 12 chars.
func ja4SHA12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ja4ALPNCode derives the a-section ALPN token from the first ALPN value
// (JA4.md "ALPN Extension Value"): the first and last ASCII alphanumeric
// characters of the value; a single-character value doubles ("h" -> "hh");
// no ALPN extension / no values / empty first value = "00"; when the first
// or last byte is not ASCII alphanumeric the token is the first and last
// characters of the value's HEX representation instead. Verified against
// all eight published JA4.md rows (0x30 0xab 0xcd 0x31's ENDS are both
// alphanumeric — '0','1' — so it takes the direct path to "01", exactly as
// published; 0xab->"ab"/0x20->"20" come from first+last of the 2-character
// hex themselves).
func ja4ALPNCode(alpn [][]byte) string {
	if len(alpn) == 0 {
		return "00"
	}
	v := alpn[0]
	if len(v) == 0 {
		return "00"
	}
	if ascAlnumByte(v[0]) && ascAlnumByte(v[len(v)-1]) {
		return string([]byte{v[0], v[len(v)-1]})
	}
	// hex fallback: first and last characters of the lower-case hex of the
	// first ALPN value.
	hxs := hex.EncodeToString(v)
	return string([]byte{hxs[0], hxs[len(hxs)-1]})
}

// ascAlnumByte reports b in [0-9A-Za-z].
func ascAlnumByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}
