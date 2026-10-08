package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// githubSlug reproduces GitHub's GFM heading-anchor algorithm. It was
// byte-verified against the rendered github.com blob of PRD.md v4 on
// 2026-10-08 (117/117 heading anchors matched) — see issue #60.
//
// Rules: lowercase; strip everything that is not a letter, digit,
// underscore or hyphen (spaces around stripped chars therefore run
// together into consecutive hyphens); every space becomes one hyphen.
func githubSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-',
			unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

var reH2 = regexp.MustCompile(`(?m)^## (.+)$`)
var reH3Num = regexp.MustCompile(`(?m)^### 2\.(\d+) `)
var reTocLink = regexp.MustCompile(`\]\(#([^)]+)\)`)

func readPRD(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("PRD.md")
	if err != nil {
		t.Fatalf("read PRD.md: %v", err)
	}
	return string(b)
}

// TestPRDSection2Contiguity fails while the D-ladder skips §2.5
// (D5 at §2.6, D6 at §2.7). See issue #60.
func TestPRDSection2Contiguity(t *testing.T) {
	prd := readPRD(t)
	ms := reH3Num.FindAllStringSubmatch(prd, -1)
	if len(ms) == 0 {
		t.Fatal("no numbered §2.x headings found")
	}
	want := 1
	for _, m := range ms {
		got := 0
		for _, c := range m[1] {
			got = got*10 + int(c-'0')
		}
		if got != want {
			t.Fatalf("§2 numbering gap: found §2.%d where §2.%d expected (found: %v)",
				got, want, seq(ms))
		}
		want++
	}
}

func seq(ms [][]string) string {
	var parts []string
	for _, m := range ms {
		parts = append(parts, "2."+m[1])
	}
	return strings.Join(parts, ", ")
}

// TestPRDTableOfContentsAnchors fails while the manual TOC uses
// single-dash slugs for headings containing & or — (GitHub slugger
// renders those as --). See issue #60.
func TestPRDTableOfContentsAnchors(t *testing.T) {
	prd := readPRD(t)

	anchor := map[string]string{} // slug -> heading text
	seen := map[string]int{}
	for _, m := range reH2.FindAllStringSubmatch(prd, -1) {
		text := strings.TrimSpace(m[1])
		s := githubSlug(text)
		if prev, dup := seen[s]; dup {
			s = s + "-" + itoa(prev+1) // GitHub dedupe suffix
		}
		seen[s]++
		anchor[s] = text
	}

	failed := 0
	for _, m := range reTocLink.FindAllStringSubmatch(prd, -1) {
		target := m[1]
		if _, ok := anchor[target]; !ok {
			failed++
			t.Errorf("TOC link #%s does not resolve to any '## ' heading anchor", target)
		}
	}
	if failed > 0 {
		t.Fatalf("%d of %d TOC links unresolved", failed, len(reTocLink.FindAllString(prd, -1)))
	}
	if len(anchor) < 20 {
		t.Fatalf("suspiciously few H2 headings parsed: %d", len(anchor))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
