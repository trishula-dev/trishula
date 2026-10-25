package fastpathdifferential

// model.go carries the userspace projection of the committed route-mark
// template (bpf/route_mark.c at the census record's tracked state): one
// decision per synthetic frame, the same header checks, the same bounded
// request-line scan, the same LPM row read, the same fail-open miss. The
// kernel-gated leg (e2e_diff_linux_test.go) proves the projection against
// the real object; until that leg runs, this file is the only decision
// stream the harness has.
//
// The projection is harness-owned: it adds no production API and claims
// no enforcement. The template contract bounds live in
// internal/fastpath/route_template.go; the staged rows come from
// routetemplate.Stage (the compiled row truth).

import (
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	routetemplate "github.com/trishula-dev/trishula/internal/fastpath/routetemplate"
)

// Template contract constants (bpf/route_mark.c); the model mirrors them
// so a template-bound change names itself here.
const (
	reqSnapMax     = 96 // the bounded request-line read
	routePrefixMax = 64 // the LPM key width in bytes
	// The TR-196 CEL-class bounds (bpf/flow_tc.c's fp leg); the model
	// mirrors them so a template-bound change names itself here.
	celMethodExtractMax = 8  // the method-token scan window
	celScanPathMax      = 64 // the bounded path extract
	celScanQueryMax     = 32 // the bounded query extract
	// The TC verdicts the program returns (the uABI constants the C
	// inlines; TC_ACT_OK and TC_ACT_SHOT are frozen since forever).
	tcActOK   uint32 = 0
	tcActShot uint32 = 2
)

// Decision is the fast-path decision stream's read for one frame: the
// outcome (drop or forward), whether a staged row matched, and which row
// (the mark value, the row index in policy order).
type Decision struct {
	// Drop marks a stop (the template returned TC_ACT_SHOT).
	Drop bool
	// Marked marks a staged-row match (the template wrote the mark).
	Marked bool
	// RowID is the matched row's index in policy order (the mark value).
	RowID uint32
}

// DefaultForward is the decision of every miss: the template's default
// forward, fail-open (no drop without a compiled drop-row match).
func DefaultForward() Decision { return Decision{} }

// BuildFrame builds the synthetic ethernet/IP/TCP frame one case asks for:
// the ethertype (ipv4|ipv6), the TCP data offset, the request line bytes
// and the 'x' pad. The kernel test-run surface reads the frame bytes as
// the skb; the model reads the same bytes, so both streams parse one
// input, never two.
func BuildFrame(f Frame) []byte {
	payload := make([]byte, 0, len(f.Line)+f.Pad)
	payload = append(payload, f.Line...)
	for i := 0; i < f.Pad; i++ {
		payload = append(payload, 'x')
	}
	var out []byte
	switch f.EtherType {
	case "ipv6":
		// A full IPv6/TCP frame: the template returns at the ethertype
		// check, the header bytes only keep the frame realistic.
		out = make([]byte, 14+40+20+len(payload))
		out[12], out[13] = 0x86, 0xDD
		out[14] = 0x60 // version 6
		out[20] = 6    // next header: TCP
		tcp := 14 + 40
		fillTCP(out[tcp:tcp+20], f.TCPDoff)
		copy(out[tcp+20:], payload)
	default:
		// IPv4 with the 20-byte header (ihl 5) the template parses.
		out = make([]byte, 14+20+20+len(payload))
		out[12], out[13] = 0x08, 0x00
		out[14] = 0x45 // version 4, ihl 5
		out[14+9] = 6  // protocol: TCP
		tcp := 14 + 20
		fillTCP(out[tcp:tcp+20], f.TCPDoff)
		copy(out[tcp+20:], payload)
	}
	return out
}

// fillTCP writes the don't-care TCP header fields with the case's data
// offset (the malformed class drives it under 5).
func fillTCP(hdr []byte, doff int) {
	hdr[12] = byte(doff << 4)
	hdr[13] = 0x18 // PSH|ACK
}

// TemplateDecision projects the committed route-mark template over one
// frame: byte-for-byte the C decisions (the miss forward, the scan caps,
// the size-word mask, the NUL-shortened key, the longest-prefix match).
// The rows are the staged compiled rows (routetemplate.Stage).
func TemplateDecision(rows []routetemplate.RouteStage, frame []byte) Decision {
	// eth: 14 bytes; the template proceeds on IPv4 only.
	if len(frame) < 14 || frame[12] != 0x08 || frame[13] != 0x00 {
		return DefaultForward()
	}
	// ip: the struct bound needs 20 bytes past eth; ihl >= 5, protocol TCP.
	if len(frame) < 14+20 {
		return DefaultForward()
	}
	ihl := int(frame[14] & 0x0F)
	if ihl < 5 || frame[14+9] != 6 {
		return DefaultForward()
	}
	// tcp: the struct bound needs 20 bytes; doff >= 5.
	tcp := 14 + ihl*4
	if len(frame) < tcp+20 {
		return DefaultForward()
	}
	doff := int(frame[tcp+12] >> 4)
	if doff < 5 {
		return DefaultForward()
	}
	reqOff := tcp + doff*4
	if len(frame) <= reqOff {
		return DefaultForward()
	}
	// The size word: the landed kernel program masks it and re-clamps
	// (the census record's template section); a wrapped zero reads as a
	// parse miss.
	n := (len(frame) - reqOff) & 0xFF
	if n > reqSnapMax {
		n = reqSnapMax
	}
	if n < 1 {
		return DefaultForward()
	}
	buf := frame[reqOff : reqOff+n]

	// Scan one: the first space at index >= 1 starts the path.
	p0 := 0
	for i := 1; i < reqSnapMax; i++ {
		if i >= n {
			break
		}
		if buf[i] == ' ' {
			p0 = i
			break
		}
	}
	if p0 == 0 || p0 >= n {
		return DefaultForward()
	}

	// Scan two: the path bytes stop at space, CR or LF; the copy caps at
	// the template key width.
	var key [routePrefixMax]byte
	d := 0
	for i := p0 + 1; i < reqSnapMax; i++ {
		if i >= n || d >= routePrefixMax {
			break
		}
		c := buf[i]
		if c == ' ' || c == '\r' || c == '\n' {
			break
		}
		key[d] = c
		d++
	}
	if d == 0 {
		return DefaultForward()
	}

	// The key length reads to the first zero byte: a NUL inside the path
	// shortens the key (the wired comment's miss reads as a shorter-key
	// match, the corpus pins the observed shape).
	keyLen := 0
	for i := 0; i < routePrefixMax; i++ {
		if key[i] == 0 {
			break
		}
		keyLen++
	}
	// The LPM row read: the longest staged prefix the key covers. Every
	// staged prefix is byte-aligned (Stage rejects no other kind).
	best := -1
	for _, r := range rows {
		pl := int(r.PrefixLenBits) / 8
		if pl == 0 || pl > keyLen {
			continue
		}
		if !prefixEqual(r.Prefix[:pl], key[:pl]) {
			continue
		}
		if best < 0 || pl > best {
			best = pl
		}
	}
	if best < 0 {
		return DefaultForward()
	}
	return rowDecision(rows, best)
}

// prefixEqual compares two byte slices.
func prefixEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The TR-196 CEL-class bounds (bpf/flow_tc.c's fp leg); the model mirrors
// them so a template-bound change names itself here.

// CELRulesDecision projects the compiled CEL-class rows over one frame
// (the C leg's decisions byte-for-byte): the bounded method/path/query
// extract, the per-row leg compares (the compare method, the decomposed
// glob prefix/suffix, the query substring scan), the first match wins
// with its compiled action, and every parse miss or absent leg forwards
// (fail-open). The quirk rows the model and the C share: a path that
// overruns the extract cap cannot back a suffix or exact leg (the kernel
// cannot see the true tail), so such rows skip; a query past the scan cap
// reads only the capped window (a false negative only — fail-open).
func CELRulesDecision(rows []fastpath.FastPathCELRule, frame []byte) Decision {
	// eth: 14 bytes; the fp leg runs on IPv4 only (the flow leg parses
	// both families; the corpus frames the v4 shape).
	if len(frame) < 14 || frame[12] != 0x08 || frame[13] != 0x00 {
		return DefaultForward()
	}
	if len(frame) < 14+20 {
		return DefaultForward()
	}
	ihl := int(frame[14] & 0x0F)
	if ihl < 5 || frame[14+9] != 6 {
		return DefaultForward()
	}
	tcp := 14 + ihl*4
	if len(frame) < tcp+20 {
		return DefaultForward()
	}
	doff := int(frame[tcp+12] >> 4)
	if doff < 5 {
		return DefaultForward()
	}
	reqOff := tcp + doff*4
	if len(frame) <= reqOff {
		return DefaultForward()
	}
	body := frame[reqOff:]

	// The method token: up to 8 bytes before the first space.
	method := []byte(nil)
	methodLen := 0
	for i := 0; i < celMethodExtractMax && i < len(body); i++ {
		if body[i] == ' ' {
			method = body[:i]
			methodLen = i
			break
		}
	}
	if method == nil {
		// No space inside the method window: the path and the query
		// cannot extract; no row matches (fail-open).
		return DefaultForward()
	}

	// The path: from the method end to a space, CR, LF or '?', capped at
	// the extract bound (the C loops the same window).
	p0 := methodLen
	pathStart := p0 + 1
	path := body[pathStart:min(len(body), pathStart+celScanPathMax)]
	terminated := false
	qAt := -1
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '?' {
			qAt = pathStart + i
			path = path[:i]
			terminated = true
			break
		}
		if c == ' ' || c == '\r' || c == '\n' {
			path = path[:i]
			terminated = true
			break
		}
	}
	// The overrun marker: the extract hit the cap and the byte past it is
	// not a terminator (the C reads the same byte through the helper).
	pathContinue := false
	if len(path) == celScanPathMax && !terminated && pathStart+celScanPathMax < len(body) {
		next := body[pathStart+celScanPathMax]
		if next != ' ' && next != '\r' && next != '\n' {
			pathContinue = true
		}
	}
	if len(path) == 0 && qAt < 0 {
		// An empty target with no query (a line ending in two spaces):
		// the leg has nothing to compare; no row matches.
		return DefaultForward()
	}

	// The query: after the '?' to a space, CR or LF, capped at the scan
	// bound (a capped miss reads fail-open: a false negative only).
	var query []byte
	if qAt >= 0 {
		end := len(body)
		for i := qAt + 1; i < len(body); i++ {
			if body[i] == ' ' || body[i] == '\r' || body[i] == '\n' {
				end = i
				break
			}
		}
		query = body[qAt+1 : min(end, qAt+1+celScanQueryMax)]
	}

	for i, r := range rows {
		if r.Method != "" && string(method) != r.Method {
			continue
		}
		if r.PathExact {
			if pathContinue || len(path) != len(r.PathGlobPrefix) || string(path) != r.PathGlobPrefix {
				continue
			}
		} else if r.PathGlobPrefix != "" || r.PathGlobSuffix != "" {
			if len(path) < len(r.PathGlobPrefix) || string(path[:len(r.PathGlobPrefix)]) != r.PathGlobPrefix {
				continue
			}
			if r.PathGlobSuffix != "" {
				if pathContinue || len(path) < len(r.PathGlobSuffix) {
					continue
				}
				if string(path[len(path)-len(r.PathGlobSuffix):]) != r.PathGlobSuffix {
					continue
				}
			}
		}
		if r.QuerySubstring != "" {
			found := false
			for s := 0; len(r.QuerySubstring)+s <= len(query); s++ {
				if string(query[s:s+len(r.QuerySubstring)]) == r.QuerySubstring {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		return rowDecisionCEL(r, uint32(i))
	}
	return DefaultForward()
}

// rowDecisionCEL renders the matched CEL row's decision (the part-1
// primitives: forward+mark, drop).
func rowDecisionCEL(r fastpath.FastPathCELRule, id uint32) Decision {
	d := Decision{Marked: true, RowID: id}
	if r.Action == fastpath.RouteTemplateActionDrop {
		d.Drop = true
	}
	return d
}

// rowDecision renders the matched row's action (the part-1 primitives:
// forward 0, drop 1) and its row id (the mark value).
func rowDecision(rows []routetemplate.RouteStage, plen int) Decision {
	for _, r := range rows {
		if int(r.PrefixLenBits)/8 != plen {
			continue
		}
		d := Decision{Marked: true, RowID: r.ID}
		if r.Action == fastpath.RouteTemplateActionDrop {
			d.Drop = true
		}
		return d
	}
	// Unreachable over staged rows: the LPM loop above proved the prefix.
	return DefaultForward()
}
