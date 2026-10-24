// Command wire converts the §11.8 differential corpus into raw HTTP/1.1
// request wire files, one file per case, for the module-1 lab replay leg.
//
// TR-27a (issue #169, spec §7.2): Module 1's teaching corpus is exactly the
// differential corpus of spec §11.8. The converter reuses the harness's own
// strict corpus loader (crsdifferential.LoadCorpus), so the lab replays the
// same bytes the parity gate scores. Output files carry the case name and
// end in .http; attackdemo crs (the S2 reference-evaluator replay surface)
// reads one file per case.
//
// Wire shape (RFC 9112): request line + header block + CRLF blank line +
// optional body. Header emission order is sorted (deterministic wire files).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	crsdifferential "github.com/trishula-dev/trishula/test/crs-differential"
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wire: FAIL: %v\n", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		fatal(fmt.Errorf("usage: wire <output-dir>"))
	}
	outDir := os.Args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}

	corpus, err := crsdifferential.LoadCorpus()
	if err != nil {
		fatal(err)
	}
	if len(corpus.Cases) == 0 {
		fatal(fmt.Errorf("corpus loaded with zero cases"))
	}

	written := 0
	for _, c := range corpus.Cases {
		wire, err := wireRequest(c)
		if err != nil {
			fatal(fmt.Errorf("case %s: %w", c.Name, err))
		}
		path := filepath.Join(outDir, c.Name+".http")
		if err := os.WriteFile(path, []byte(wire), 0o644); err != nil {
			fatal(err)
		}
		written++
	}
	fmt.Printf("wire: %d raw HTTP/1.1 request files from the §11.8 corpus (out: %s)\n", written, outDir)
}

// wireRequest renders one corpus case as raw HTTP/1.1 request bytes.
func wireRequest(c crsdifferential.Case) (string, error) {
	r := c.Request
	if r.Method == "" || r.URI == "" {
		return "", fmt.Errorf("case carries no method/uri")
	}
	version := r.Version
	if version == "" {
		version = "1.1"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/%s\r\n", r.Method, r.URI, version)

	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sawContentLength := false
	for _, k := range keys {
		if strings.EqualFold(k, "Content-Length") {
			sawContentLength = true
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, r.Headers[k])
	}
	// The wire file carries the body's exact byte count when the corpus
	// case does not (the raw request must frame its own body).
	body := r.Body
	if body != "" && !sawContentLength {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if body != "" {
		b.WriteString(body)
	}
	return b.String(), nil
}
