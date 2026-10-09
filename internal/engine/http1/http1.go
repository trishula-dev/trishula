// Package http1 reconstructs an HTTP/1 request from wire bytes into the
// §11.3 structured request view (TR-05b; PRD §11.3 request.method/path and
// the view grown field-by-field — no speculative fields).
//
// This slice reads the request HEAD ONLY — no body reads (TR-05b
// acceptance: allocation-bounded, malformed-input cases explicit). The
// parser is strictly bounded: every step consumes from a fixed-size read
// budget so a hostile peer cannot grow allocations (§9.4 kernel discipline
// mirrored in userspace: the engine never trusts unbounded input).
package http1

import (
	"errors"
	"fmt"
	"strings"
)

// Bounds (RFC 9112 §2.2 sane minimums, tightened: a v0 WAF slice never
// needs the full server maxima).
const (
	MaxLineBytes     = 8 * 1024  // request line + each header line
	MaxHeaderLines   = 100       // header count budget
	MaxHeaderBytes   = 16 * 1024 // total header-block budget
	maxMethodTokens  = 64        // method token length budget
	minRequestTokens = 3         // method SP target SP version
)

// Classification of every malformed-input case the parser can meet.
// Errors are explicit values (errors.Is-able), never bare strings.
var (
	ErrEmpty          = errors.New("http1: empty input")
	ErrLineTooLong    = errors.New("http1: line exceeds 8 KiB read budget")
	ErrTooManyHeaders = errors.New("http1: header count exceeds budget")
	ErrHeaderTooBig   = errors.New("http1: header block exceeds budget")
	ErrBadMethod      = errors.New("http1: malformed method token")
	ErrBadTarget      = errors.New("http1: malformed request target")
	ErrMissingVersion = errors.New("http1: missing HTTP version")
	ErrBadVersion     = errors.New("http1: malformed HTTP version")
	ErrBadHeader      = errors.New("http1: malformed header field")
	ErrHeaderFold     = errors.New("http1: obsolete header folding (RFC 7230 deprecated)")
	ErrNoCRLF         = errors.New("http1: request line not CRLF-terminated")
	ErrNULInLine      = errors.New("http1: NUL byte in request line")
)

// Request is the §11.3 view head scope for this slice: method/path/version
// plus the header map at S0-relevant cardinality. JSON tags rule the
// decode path (sigs.k8s.io/yaml = json-tag rules) matching cel.Request
// (TR-02) — this struct extends the same view, it does not fork it.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Version string            `json:"version"`
	Headers map[string]string `json:"headers"`
}

// Parse reconstructs one HTTP/1 request head from wire bytes. Input is the
// exact bytes the connection carried so far (headers already terminated by
// the CRLF-CRLF or connection-close convention is NOT required here: the
// slice parses the head lines it is given and stops at the blank line or
// end of input). No body reads at this slice.
func Parse(wire []byte) (*Request, error) {
	if len(wire) == 0 {
		return nil, ErrEmpty
	}
	r := &Request{Headers: map[string]string{}}
	total := 0 // header-block budget across all lines

	// --- request line -------------------------------------------------
	line, rest, err := nextLine(wire, 0)
	if err != nil {
		return nil, err
	}
	total += line.end
	method, target, version, err := parseRequestLine(line.text)
	if err != nil {
		return nil, err
	}
	r.Method, r.Path, r.Version = method, target, version

	// --- header lines ---------------------------------------------------
	headerLines := 0
	for {
		line, rest, err = nextLine(rest, total)
		if err != nil {
			return nil, err
		}
		if line.text == "" {
			break // end of head (blank line); rest carries any body prefix — unread
		}
		total += line.end
		if strings.ContainsAny(line.text[:1], " 	") {
			return nil, ErrHeaderFold // obs-fold: a continuation line starts with SP/HTAB
		}
		headerLines++
		if headerLines > MaxHeaderLines {
			return nil, ErrTooManyHeaders // line count, NOT distinct keys: duplicates still cost parse
		}
		name, value, err := parseHeaderField(line.text)
		if err != nil {
			return nil, err
		}
		r.Headers[name] = value
		if total > MaxHeaderBytes {
			return nil, ErrHeaderTooBig
		}
	}
	return r, nil
}

// lineResult is one consumed CRLF-delimited line: its de-CRLF'd text and
// the total wire bytes the line cost (budget input).
type lineResult struct {
	text string
	end  int // bytes consumed including CRLF
}

// nextLine consumes one CRLF-terminated line (max budget applies to the
// raw line, CRLF included). A bare LF anywhere before the first LF is
// tolerated only as the line terminator when no CR precedes it? — no: the
// wire is CRLF per RFC 9112 §2.2; a bare-LF line is malformed (ErrNoCRLF).
func nextLine(wire []byte, consumed int) (lineResult, []byte, error) {
	for i := 0; i < len(wire); i++ {
		if wire[i] == 0x00 {
			return lineResult{}, nil, ErrNULInLine
		}
		if i > MaxLineBytes {
			return lineResult{}, nil, ErrLineTooLong
		}
		if wire[i] != '\n' {
			continue
		}
		if i == 0 || wire[i-1] != '\r' {
			return lineResult{}, nil, ErrNoCRLF
		}
		text := string(wire[:i-1]) // strip CRLF
		return lineResult{text: text, end: i + 1}, wire[i+1:], nil
	}
	return lineResult{}, nil, ErrNoCRLF
}

// parseRequestLine splits "METHOD SP target SP HTTP/x.y" with the explicit
// malformed cases from TR-05b: bad method token (bare 0x00 is caught in
// nextLine; token chars validated here), missing/malformed version,
// missing target.
func parseRequestLine(line string) (method, target, version string, err error) {
	parts := strings.Split(line, " ")
	if len(parts) < minRequestTokens {
		// A two-token line (method SP target, no version) is the classic
		// missing-version shape; a single token is worse (ErrMissingVersion
		// would lie) — classify by token count.
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return "", "", "", ErrMissingVersion
		}
		return "", "", "", ErrBadTarget
	}
	// More than 3 space-separated atoms: v0 slices on the first three
	// (an origin-form target must not contain SP; keep it malformed).
	if len(parts) > 3 {
		return "", "", "", ErrBadTarget
	}
	method, target, version = parts[0], parts[1], parts[2]
	if !validMethod(method) {
		return "", "", "", fmt.Errorf("%w: %q", ErrBadMethod, trunc(method))
	}
	if target == "" || strings.ContainsAny(target, " \t") {
		return "", "", "", ErrBadTarget
	}
	if !strings.HasPrefix(version, "HTTP/") || len(version) != 8 {
		return "", "", "", ErrBadVersion
	}
	maj, min := version[5], version[7]
	if version[6] != '.' || maj < '0' || maj > '9' || min < '0' || min > '9' {
		return "", "", "", ErrBadVersion
	}
	// v0 slice pin: HTTP/1.0 and HTTP/1.1 only. HTTP/2 arrives over an
	// HTTP/1.1 Upgrade (TR-15); 0.9 is version-less by construction;
	// everything else does not exist on an HTTP/1 wire.
	if maj != '1' || (min != '0' && min != '1') {
		return "", "", "", fmt.Errorf("%w: %s not in the v0 slice {HTTP/1.0, HTTP/1.1}", ErrBadVersion, version)
	}
	return method, target, version, nil
}

// validMethod checks the RFC 9110 §9.1 token grammar (tchar set).
func validMethod(m string) bool {
	if m == "" || len(m) > maxMethodTokens {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// parseHeaderField splits "Name: value" (RFC 9112 §5.1) and validates the
// field-name token grammar. Value is OWS-trimmed once (no fold handling —
// obs-fold is rejected at the line level).
func parseHeaderField(line string) (name, value string, err error) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return "", "", ErrBadHeader
	}
	name, value = line[:colon], line[colon+1:]
	if !validFieldName(name) {
		return "", "", ErrBadHeader
	}
	value = strings.Trim(value, " \t")
	return name, value, nil
}

// validFieldName checks the RFC 9110 §5.6.2 token grammar for header
// names (same tchar set as methods).
func validFieldName(n string) bool { return validMethod(n) }

// trunc bounds echoed tokens inside error text.
func trunc(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "…"
}
