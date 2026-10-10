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

// ja4f computes the JA4 render. GREEN fills this; RED stub fails.
func ja4f(ch *ClientHelloSummary) ja4Result { return ja4Result{} }
