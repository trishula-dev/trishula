package http1

import (
	"errors"
	"strings"
	"testing"
)

// mustParse is the clean-path helper: parses wire or fails the test.
func mustParse(t *testing.T, wire string) *Request {
	t.Helper()
	r, err := Parse([]byte(wire))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return r
}

// TestCleanRequestParses is the §11.3-view happy path: the seed rule's own
// request shape (POST /v1/chat/completions) reconstructed from wire bytes.
func TestCleanRequestParses(t *testing.T) {
	wire := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"User-Agent: probe/1\r\n" +
		"\r\n"
	r := mustParse(t, wire)
	if r.Method != "POST" {
		t.Errorf("method: got %q, want POST", r.Method)
	}
	if r.Path != "/v1/chat/completions" {
		t.Errorf("path: got %q, want /v1/chat/completions", r.Path)
	}
	if r.Version != "HTTP/1.1" {
		t.Errorf("version: got %q, want HTTP/1.1", r.Version)
	}
	if r.Headers["Host"] != "api.example.com" {
		t.Errorf("host header: got %q", r.Headers["Host"])
	}
	if r.Headers["Content-Type"] != "application/json" {
		t.Errorf("content-type header: got %q", r.Headers["Content-Type"])
	}
	if len(r.Headers) != 3 {
		t.Errorf("header count: got %d, want 3", len(r.Headers))
	}
}

// TestParseStopsAtBlankLine pins the head-only contract: bytes after the
// blank line (a body prefix) are never read.
func TestParseStopsAtBlankLine(t *testing.T) {
	wire := "GET /x HTTP/1.1\r\nHost: h\r\n\r\nTHIS IS BODY PREFIX"
	r := mustParse(t, wire)
	if r.Method != "GET" || r.Path != "/x" {
		t.Errorf("head parse drifted: %+v", r)
	}
}

// TestOWSValueTrim pins single-space OWS trimming of header values.
func TestOWSValueTrim(t *testing.T) {
	r := mustParse(t, "GET / HTTP/1.1\r\nX-A:   spaced  \r\n\r\n")
	if r.Headers["X-A"] != "spaced" {
		t.Errorf("value trim: got %q, want spaced", r.Headers["X-A"])
	}
}

// TestEmptyInput errs, never panics.
func TestEmptyInput(t *testing.T) {
	if _, err := Parse(nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("nil input: got %v, want ErrEmpty", err)
	}
	if _, err := Parse([]byte{}); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty input: got %v, want ErrEmpty", err)
	}
}

// TestMalformedShapes pins every TR-05b malformed case to its classified
// error — each must be errors.Is-matched and must never panic.
func TestMalformedShapes(t *testing.T) {
	cases := []struct {
		name string
		wire string
		want error
	}{
		{"bare-NUL-in-method", "GE\x00T /x HTTP/1.1\r\n\r\n", ErrNULInLine},
		{"oversized-first-line", "GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\n\r\n", ErrLineTooLong},
		{"missing-version", "GET /x\r\n\r\n", ErrMissingVersion},
		{"bad-version-text", "GET /x HTTPSOMETHING/\r\n\r\n", ErrBadVersion},
		{"bad-version-length", "GET /x HTTP/11\r\n\r\n", ErrBadVersion},
		{"bad-method-token", "G ET /x HTTP/1.1\r\n\r\n", ErrBadTarget},   // 4 atoms: target-atom rule fires
		{"lowercase-invalid-ish-method", "get /x HTTP/1.1\r\n\r\n", nil}, // token-legal per tchar — allowed
		{"no-crlf-bare-lf", "GET /x HTTP/1.1\n\r\n", ErrNoCRLF},
		{"nul-in-target", "GET /x\x00 HTTP/1.1\r\n\r\n", ErrNULInLine},
		{"header-fold-continuation", "GET /x HTTP/1.1\r\nX-A: v\r\n  folded\r\n\r\n", ErrHeaderFold},
		{"header-no-colon", "GET /x HTTP/1.1\r\nBadHeader\r\n\r\n", ErrBadHeader},
		{"header-space-in-name", "GET /x HTTP/1.1\r\nBad Name: v\r\n\r\n", ErrBadHeader},
		{"header-name-empty", "GET /x HTTP/1.1\r\n: v\r\n\r\n", ErrBadHeader},
		{"too-many-headers", "GET /x HTTP/1.1\r\n" + manyHeaders(101) + "\r\n", ErrTooManyHeaders},
		{"header-block-too-big", "GET /x HTTP/1.1\r\n" + bigHeader(17*1024) + "\r\n", ErrHeaderTooBig},
	}
	for _, tc := range cases {
		r, err := Parse([]byte(tc.wire))
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: clean case errored: %v", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: no error (request=%+v), want %v", tc.name, r, tc.want)
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func manyHeaders(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("X-T: v\r\n")
	}
	return b.String()
}

func bigHeader(total int) string {
	v := strings.Repeat("a", total-8)
	return "X-B: " + v + "\r\n"
}

// TestParseNeverPanicsFuzzSeeds hammers structurally evil inputs: any
// panic is the defect — classification correctness is the case table's job.
func TestParseNeverPanicsFuzzSeeds(t *testing.T) {
	seeds := []string{
		"", "\r", "\r\n", "\n", "\r\r\n", "\x00", "\x00\r\n",
		"GET", "GET ", "GET  ", "GET  HTTP/1.1", "GET / HTTP/1.",
		"GET / HTTP/1.1\r\nX", "GET / HTTP/1.1\r\nX:",
		"GET / HTTP/1.1\r\n:\r\n\r\n", "GET / HTTP/1.1\r\n\r",
		strings.Repeat("GET /x HTTP/1.1\r\n", 50),
		"GET /" + strings.Repeat("/", 500) + " HTTP/1.1\r\n\r\n",
		"\tGET /x HTTP/1.1\r\n\r\n",
		"GE\x01TF /x HTTP/1.1\r\n\r\n",
	}
	for i, s := range seeds {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("seed %d panicked: %v", i, r)
				}
			}()
			_, _ = Parse([]byte(s))
		}()
	}
}

// TestVersionAcceptanceMatrix pins the accepted version set.
func TestVersionAcceptanceMatrix(t *testing.T) {
	for _, v := range []string{"HTTP/1.0", "HTTP/1.1"} {
		r, err := Parse([]byte("GET / HTTP/" + v[len("HTTP/"):] + "\r\n\r\n"))
		if err != nil || r.Version != v {
			t.Errorf("version %s: got %v/%v", v, r, err)
		}
	}
	for _, v := range []string{"HTTP/1.2", "HTTP/9.9", "HTTP/0.9"} {
		_, err := Parse([]byte("GET / " + v + "\r\n\r\n"))
		if !errors.Is(err, ErrBadVersion) {
			t.Errorf("version %s accepted (v0 slice pins 1.0/1.1), err=%v", v, err)
		}
	}
}
