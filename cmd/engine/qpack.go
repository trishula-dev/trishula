package main

// TR-203 L3 (issue #264 leaf 3) — the QPACK subset for the inline H3
// listener (RFC 9204). The listener announces SETTINGS_QPACK_MAX_TABLE_CAPACITY
// = 0 (setting 0x1) in its control-stream SETTINGS frame. A client of a
// conforming encoder therefore reports Required Insert Count 0 and encodes
// with static-table references and literals only. A dynamic reference or a
// nonzero Required Insert Count errors the field section
// (QPACK_DECOMPRESSION_FAILED, 0x200) — the listener never silently
// mishandles an unannounced dynamic table.
//
// The string primitives (prefixed integers, the Huffman table) follow
// RFC 7541 sections 5.1/5.2 unmodified (RFC 9204, section 4.1). The Huffman
// codec comes from golang.org/x/net/http2/hpack (the repo's pinned
// x/net module carries it; the package is already a repo import surface via
// test/gateway-conformance). The encoder side (responses) writes literal
// field lines and keeps the no-Huffman choice; a QPACK decoder accepts both
// string forms.

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// QPACK static table (RFC 9204, Appendix A). The 99 entries below read
// verbatim from the RFC's table (the RFC's display line breaks inside values
// are formatting; the strings here carry the joined values).
var qpackStatic = [99]hpack.HeaderField{
	{Name: ":authority", Value: ""},
	{Name: ":path", Value: "/"},
	{Name: "age", Value: "0"},
	{Name: "content-disposition", Value: ""},
	{Name: "content-length", Value: "0"},
	{Name: "cookie", Value: ""},
	{Name: "date", Value: ""},
	{Name: "etag", Value: ""},
	{Name: "if-modified-since", Value: ""},
	{Name: "if-none-match", Value: ""},
	{Name: "last-modified", Value: ""},
	{Name: "link", Value: ""},
	{Name: "location", Value: ""},
	{Name: "referer", Value: ""},
	{Name: "set-cookie", Value: ""},
	{Name: ":method", Value: "CONNECT"},
	{Name: ":method", Value: "DELETE"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "HEAD"},
	{Name: ":method", Value: "OPTIONS"},
	{Name: ":method", Value: "POST"},
	{Name: ":method", Value: "PUT"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "103"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "503"},
	{Name: "accept", Value: "*/*"},
	{Name: "accept", Value: "application/dns-message"},
	{Name: "accept-encoding", Value: "gzip, deflate, br"},
	{Name: "accept-ranges", Value: "bytes"},
	{Name: "access-control-allow-headers", Value: "cache-control"},
	{Name: "access-control-allow-headers", Value: "content-type"},
	{Name: "access-control-allow-origin", Value: "*"},
	{Name: "cache-control", Value: "max-age=0"},
	{Name: "cache-control", Value: "max-age=2592000"},
	{Name: "cache-control", Value: "max-age=604800"},
	{Name: "cache-control", Value: "no-cache"},
	{Name: "cache-control", Value: "no-store"},
	{Name: "cache-control", Value: "public, max-age=31536000"},
	{Name: "content-encoding", Value: "br"},
	{Name: "content-encoding", Value: "gzip"},
	{Name: "content-type", Value: "application/dns-message"},
	{Name: "content-type", Value: "application/javascript"},
	{Name: "content-type", Value: "application/json"},
	{Name: "content-type", Value: "application/x-www-form-urlencoded"},
	{Name: "content-type", Value: "image/gif"},
	{Name: "content-type", Value: "image/jpeg"},
	{Name: "content-type", Value: "image/png"},
	{Name: "content-type", Value: "text/css"},
	{Name: "content-type", Value: "text/html; charset=utf-8"},
	{Name: "content-type", Value: "text/plain"},
	{Name: "content-type", Value: "text/plain;charset=utf-8"},
	{Name: "range", Value: "bytes=0-"},
	{Name: "strict-transport-security", Value: "max-age=31536000"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains; preload"},
	{Name: "vary", Value: "accept-encoding"},
	{Name: "vary", Value: "origin"},
	{Name: "x-content-type-options", Value: "nosniff"},
	{Name: "x-xss-protection", Value: "1; mode=block"},
	{Name: ":status", Value: "100"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "302"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "403"},
	{Name: ":status", Value: "421"},
	{Name: ":status", Value: "425"},
	{Name: ":status", Value: "500"},
	{Name: "accept-language", Value: ""},
	{Name: "access-control-allow-credentials", Value: "FALSE"},
	{Name: "access-control-allow-credentials", Value: "TRUE"},
	{Name: "access-control-allow-headers", Value: "*"},
	{Name: "access-control-allow-methods", Value: "get"},
	{Name: "access-control-allow-methods", Value: "get, post, options"},
	{Name: "access-control-allow-methods", Value: "options"},
	{Name: "access-control-expose-headers", Value: "content-length"},
	{Name: "access-control-request-headers", Value: "content-type"},
	{Name: "access-control-request-method", Value: "get"},
	{Name: "access-control-request-method", Value: "post"},
	{Name: "alt-svc", Value: "clear"},
	{Name: "authorization", Value: ""},
	{Name: "content-security-policy", Value: "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{Name: "early-data", Value: "1"},
	{Name: "expect-ct", Value: ""},
	{Name: "forwarded", Value: ""},
	{Name: "if-range", Value: ""},
	{Name: "origin", Value: ""},
	{Name: "purpose", Value: "prefetch"},
	{Name: "server", Value: ""},
	{Name: "timing-allow-origin", Value: "*"},
	{Name: "upgrade-insecure-requests", Value: "1"},
	{Name: "user-agent", Value: ""},
	{Name: "x-forwarded-for", Value: ""},
	{Name: "x-frame-options", Value: "deny"},
	{Name: "x-frame-options", Value: "sameorigin"},
}

// qpackStatusStatic maps the :status values the static table carries
// (indices 24-28 plus 63-71) for the encoder's indexed rows.
var qpackStatusStatic = map[string]int{
	"103": 24, "200": 25, "304": 26, "404": 27, "503": 28,
	"100": 63, "204": 64, "206": 65, "302": 66, "400": 67,
	"403": 68, "421": 69, "425": 70, "500": 71,
}

// errQpackDecompressionFailed = RFC 9204's dynamic-table-state violation; the
// listener maps it to HTTP/3 error QPACK_DECOMPRESSION_FAILED (0x200).
var errQpackDecompressionFailed = errors.New("qpack: field section needs the dynamic table (capacity 0 announced)")

// errQpackTrailing = a truncated or overlong field-section byte string.
var errQpackTrailing = errors.New("qpack: field section ends mid-instruction")

// qpackCursor walks one encoded field section byte by byte. HPACK-style
// instructions start on a byte boundary; the string literals may start
// mid-byte (RFC 9204, section 4.1.2, the N-bit prefix string).
type qpackCursor struct {
	b []byte
	i int
}

// byteNext reads the current byte and advances.
func (c *qpackCursor) byteNext() (byte, error) {
	if c.i >= len(c.b) {
		return 0, errQpackTrailing
	}
	b := c.b[c.i]
	c.i++
	return b, nil
}

// qpackReadPrefixedInt reads one RFC 7541 section 5.1 prefixed integer whose
// first prefix bits sit in firstByte. prefixBits = the full width (7 = an
// 8-bit-prefixed integer minus... no: the width here = the integer's own
// prefix bits inside the byte, e.g. 6 for the indexed field line).
func qpackReadPrefixedInt(c *qpackCursor, prefixBits int, firstByte byte) (uint64, error) {
	if prefixBits < 1 || prefixBits > 8 {
		return 0, fmt.Errorf("qpack: bad prefix width %d", prefixBits)
	}
	if prefixBits == 8 {
		return uint64(firstByte), nil
	}
	mask := uint64(1)<<uint(prefixBits) - 1
	value := uint64(firstByte) & mask
	if value < mask {
		return value, nil
	}
	var b byte
	var err error
	var shift uint
	for {
		b, err = c.byteNext()
		if err != nil {
			return 0, errQpackTrailing
		}
		value += uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			return value, nil
		}
	}
}

// qpackReadPrefixedString reads one string literal (RFC 7541 section 5.2):
// the first prefixBits carry the Huffman flag and the length prefix. A
// Huffman-coded string decodes through golang.org/x/net/http2/hpack (the
// RFC 7541 Appendix B table, unmodified).
func qpackReadPrefixedString(c *qpackCursor, prefixBits int, firstByte byte) (hpack.HeaderField, error) {
	if prefixBits < 2 {
		return hpack.HeaderField{}, fmt.Errorf("qpack: bad string prefix width %d", prefixBits)
	}
	huff := firstByte&(1<<uint(prefixBits-1)) != 0
	length, err := qpackReadPrefixedInt(c, prefixBits-1, firstByte)
	if err != nil {
		return hpack.HeaderField{}, err
	}
	if int(length) > len(c.b)-c.i {
		return hpack.HeaderField{}, errQpackTrailing
	}
	raw := c.b[c.i : c.i+int(length)]
	c.i += int(length)
	if !huff {
		return hpack.HeaderField{Value: string(raw)}, nil
	}
	decoded, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return hpack.HeaderField{}, err
	}
	return hpack.HeaderField{Value: decoded}, nil
}

// qpackDecodeHeaderBlock decodes one encoded field section under the
// capacity-0 shape (RFC 9204, sections 4.5.1 and 4.5.2-4.5.6). A Required
// Insert Count other than 0, a dynamic reference or a post-base instruction
// errors the block: the listener announced capacity 0 and a conforming
// encoder never builds such a block.
func qpackDecodeHeaderBlock(block []byte) ([]hpack.HeaderField, error) {
	c := &qpackCursor{b: block}
	// the prefix: Required Insert Count (8-bit prefixed) + S/DeltaBase
	// (7-bit prefixed). The shape records both; the capacity-0 decoder
	// accepts only Required Insert Count = 0.
	first, err := c.byteNext()
	if err != nil {
		return nil, errQpackTrailing
	}
	// an 8-bit-prefixed integer = the whole first byte (RFC 7541 5.1). A
	// count other than 0 references dynamic state the capacity-0 decoder
	// never has.
	if first != 0 {
		return nil, errQpackDecompressionFailed
	}
	baseByte, err := c.byteNext()
	if err != nil {
		return nil, errQpackTrailing
	}
	_ = baseByte // S + Delta Base; only dynamic/post-base instructions read it

	fields := make([]hpack.HeaderField, 0, 8)
	for c.i < len(c.b) {
		b, err := c.byteNext()
		if err != nil {
			return nil, errQpackTrailing
		}
		switch {
		case b&0x80 != 0:
			// indexed field line: 1 | T | index (6+). T=1 static.
			if b&0x40 == 0 {
				return nil, errQpackDecompressionFailed // dynamic index
			}
			idx, err := qpackReadPrefixedInt(c, 6, b)
			if err != nil {
				return nil, err
			}
			if idx >= 99 {
				return nil, errQpackDecompressionFailed
			}
			fields = append(fields, hpack.HeaderField{
				Name:  qpackStatic[idx].Name,
				Value: qpackStatic[idx].Value,
			})
		case b&0xC0 == 0x40:
			// literal field line with name reference: 0 1 | N | T | name
			// index (4+); the value follows as a fresh 8-bit-prefix string.
			if b&0x10 == 0 {
				return nil, errQpackDecompressionFailed // dynamic name ref
			}
			idx, err := qpackReadPrefixedInt(c, 4, b)
			if err != nil {
				return nil, err
			}
			if idx >= 99 {
				return nil, errQpackDecompressionFailed
			}
			name := qpackStatic[idx].Name
			vb, err := c.byteNext()
			if err != nil {
				return nil, errQpackTrailing
			}
			value, err := qpackReadPrefixedString(c, 8, vb)
			if err != nil {
				return nil, err
			}
			fields = append(fields, hpack.HeaderField{Name: name, Value: value.Value})
		case b&0xE0 == 0x20:
			// literal field line with literal name: 0 0 1 | N | then the
			// name as a 4-bit-prefix string in the same byte, then the
			// value as a fresh 8-bit-prefix string.
			name, err := qpackReadPrefixedString(c, 4, b)
			if err != nil {
				return nil, err
			}
			vb, err := c.byteNext()
			if err != nil {
				return nil, errQpackTrailing
			}
			value, err := qpackReadPrefixedString(c, 8, vb)
			if err != nil {
				return nil, err
			}
			fields = append(fields, hpack.HeaderField{Name: name.Value, Value: value.Value})
		default:
			// 0001 = indexed with post-base index; 000x = literal with a
			// post-base name reference. Both address the dynamic table.
			return nil, errQpackDecompressionFailed
		}
	}
	return fields, nil
}

// qpackAppendPrefixedInt encodes one RFC 7541 section 5.1 prefixed integer
// that starts a fresh byte boundary (prefixBits = the prefix width).
func qpackAppendPrefixedInt(dst []byte, prefixBits int, value uint64) []byte {
	if prefixBits < 1 || prefixBits > 8 {
		return dst
	}
	if prefixBits == 8 {
		return append(dst, byte(value))
	}
	mask := uint64(1)<<uint(prefixBits) - 1
	if value < mask {
		return append(dst, byte(value))
	}
	dst = append(dst, byte(mask))
	value -= mask
	for value >= 0x80 {
		dst = append(dst, byte(value&0x7f)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

// qpackAppendLiteralStr appends one literal field line (RFC 9204, section
// 4.5.6): the instruction byte 0b001 with N=0, then the name as the
// 4-bit-prefix string (its H flag and length prefix join the instruction
// byte), then the value as a fresh 8-bit-prefix string (the H flag sits
// on that byte's top bit). No Huffman on the encode side: both H bits stay 0.
func qpackAppendLiteralStr(dst []byte, name, value string) []byte {
	dst = append(dst, 0x20)
	dst = appendQpackStrMid(dst, 4, name)
	return appendQpackByteStr(dst, value)
}

// appendQpackByteStr appends the 8-bit-prefix (byte-aligned) string form.
func appendQpackByteStr(dst []byte, s string) []byte {
	dst = qpackAppendPrefixedInt(dst, 7, uint64(len(s)))
	return append(dst, s...)
}

// appendQpackStrMid appends the length prefix of a mid-byte string literal:
// the listener's encoder keeps the H flag clear (no Huffman on the encode
// side), so only the length bits join dst's last (pre-set) byte.
func appendQpackStrMid(dst []byte, prefixBits int, s string) []byte {
	length := uint64(len(s))
	mask := uint64(1)<<uint(prefixBits-1) - 1
	last := len(dst) - 1
	if length < mask {
		dst[last] |= byte(length)
	} else {
		dst[last] |= byte(mask)
		rest := length - mask
		for rest >= 0x80 {
			dst = append(dst, byte(rest&0x7f)|0x80)
			rest >>= 7
		}
		dst = append(dst, byte(rest))
	}
	return append(dst, s...)
}

// qpackEncodeHeaders builds one encoded field section: the capacity-0 prefix
// (Required Insert Count 0, Base 0), then every field line as a literal.
// Field lines named :status with a static-table value encode as indexed
// static field lines (RFC 9204, section 4.5.2).
func qpackEncodeHeaders(fields []hpack.HeaderField) ([]byte, error) {
	out := make([]byte, 0, 64)
	out = append(out, 0x00) // Required Insert Count = 0
	out = append(out, 0x00) // S = 0, Delta Base = 0
	for _, f := range fields {
		if f.Name == ":status" {
			if idx, ok := qpackStatusStatic[f.Value]; ok {
				// indexed field line, static (RFC 9204, section 4.5.2):
				// 1 | T=1 | index (6+). Index values above the 6-bit
				// prefix carry the continuation form (the prefix bits
				// all set, then the RFC 7541 continuation bytes).
				out = qpackAppendIndexedStatic(out, uint64(idx))
				continue
			}
		}
		out = qpackAppendLiteralStr(out, f.Name, f.Value)
	}
	return out, nil
}

// qpackAppendIndexedStatic appends one indexed field line with a static
// table reference (RFC 9204, section 4.5.2): 1 | T=1 | index (6+). Index
// values above the 6-bit prefix fill the prefix (0x3F) and carry the RFC
// 7541 continuation bytes.
func qpackAppendIndexedStatic(dst []byte, idx uint64) []byte {
	if idx < 0x3F {
		return append(dst, byte(0xC0|idx))
	}
	out := append(dst, 0xFF)
	rest := idx - 0x3F
	for rest >= 0x80 {
		out = append(out, byte(rest&0x7f)|0x80)
		rest >>= 7
	}
	return append(out, byte(rest))
}
