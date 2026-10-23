package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// githubSlug reproduces GitHub's GFM heading-anchor algorithm. It was
// byte-verified against the rendered github.com blob of spec.md v4 on
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
	b, err := os.ReadFile("spec.md")
	if err != nil {
		t.Fatalf("read spec.md: %v", err)
	}
	return string(b)
}

// TestSpecSection2Contiguity fails while the D-ladder skips a rung (each
// later decision lands one section past its D-number). See issue #60.
func TestSpecSection2Contiguity(t *testing.T) {
	prd := readPRD(t)
	ms := reH3Num.FindAllStringSubmatch(prd, -1)
	if len(ms) == 0 {
		t.Fatal("no numbered §2.x headings found") // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}
	want := 1
	for _, m := range ms {
		got := 0
		for _, c := range m[1] {
			got = got*10 + int(c-'0')
		}
		if got != want {
			t.Fatalf("§2 numbering gap: found §2.%d where §2.%d expected (found: %v)", // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
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

// TestSpecTableOfContentsAnchors fails while the manual TOC uses
// single-dash slugs for headings containing & or — (GitHub slugger
// renders those as --). See issue #60.
func TestSpecTableOfContentsAnchors(t *testing.T) {
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

// --- TR-23 (issue #23): the DX1 timed gate (the spec's DX-charter row DX1,
//
// The DX1 charter and the M3 gate name one timing: a developer's first
// custom rule is enforced ≤ 15 min from `git clone`, nightly-timed in CI.
// These invariants fail while the repo carries no documented surface for
// that gate:
//  1. lab/dx1/README.md documents the timed gate script, the ≤ 15 min
//     budget, the nightly runner and the first-enforced-rule claim, and
//     cites the spec's M3 adoption-gate anchor.
//  2. docs/academy/README.md links the DX1 lab path.
//  3. README.md names the gate script and the nightly workflow, and the
//     workflow file exists.
//  4. Every PRD anchor cite on the touched pages resolves against the
//     PRD's real heading set; every relative link points at a real repo
//     file.

var reH3 = regexp.MustCompile(`(?m)^### (.+)$`)

var rePRDAnchorLink = regexp.MustCompile(
	`\]\(https://github\.com/trishula-dev/trishula/blob/main/docs/PRD\.md#([^)]+)\)`)

var reMdLink = regexp.MustCompile(`\]\(([^)]+)\)`)

// prdHeadingAnchors returns every heading anchor spec.md exposes — ## and
// ### headings slugged with the verified GitHub algorithm and deduped the
// GitHub way — as slug → heading text.
func prdHeadingAnchors(prd string) map[string]string {
	seen := map[string]int{}
	anchors := map[string]string{}
	for _, re := range []*regexp.Regexp{reH2, reH3} {
		for _, m := range re.FindAllStringSubmatch(prd, -1) {
			text := strings.TrimSpace(m[1])
			slug := githubSlug(text)
			if prev, dup := seen[slug]; dup {
				slug = slug + "-" + itoa(prev+1) // GitHub dedupe suffix
			}
			seen[slug]++
			anchors[slug] = text
		}
	}
	return anchors
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestDX1GateDocs(t *testing.T) {
	// 1. The lab README documents the timed gate.
	labReadme := readRepoFile(t, "lab/dx1/README.md")
	for _, want := range []string{
		"dx1-gate.sh",
		"≤ 15 min",
		"nightly",
		"first enforced rule",
		"https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates",
	} {
		if !strings.Contains(labReadme, want) {
			t.Errorf("lab/dx1/README.md is missing the DX1 gate surface %q", want)
		}
	}

	// 2. The academy index links the DX1 lab path.
	academy := readRepoFile(t, "docs/academy/README.md")
	if !strings.Contains(academy, "](../../lab/dx1") {
		t.Errorf("docs/academy/README.md does not link the DX1 lab path (](../../lab/dx1)")
	}

	// 3. The README names the gate script + the nightly workflow; the
	//    workflow file exists.
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, "dx1-gate.sh") {
		t.Errorf("README.md does not name the DX1 gate script")
	}
	if !strings.Contains(readme, "lab-nightly.yml") {
		t.Errorf("README.md does not name the nightly lab workflow")
	}
	if _, err := os.Stat(filepath.Join("..", ".github", "workflows", "lab-nightly.yml")); err != nil {
		t.Errorf(".github/workflows/lab-nightly.yml is absent — the M3 nightly timing has no runner")
	}

	// 4. Cite + link integrity on the touched pages.
	prd := prdHeadingAnchors(readPRD(t))
	unresolved := 0
	for _, page := range []struct{ name, body string }{
		{"README.md", readme},
		{"docs/academy/README.md", academy},
		{"lab/dx1/README.md", labReadme},
	} {
		for _, m := range rePRDAnchorLink.FindAllStringSubmatch(page.body, -1) {
			if _, ok := prd[m[1]]; !ok {
				unresolved++
				t.Errorf("%s cites PRD anchor #%s — no PRD heading resolves to it", page.name, m[1])
			}
		}
		for _, m := range reMdLink.FindAllStringSubmatch(page.body, -1) {
			target := m[1]
			isExternal := strings.HasPrefix(target, "http://") ||
				strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "#") ||
				strings.Contains(target, "://")
			if isExternal {
				continue
			}
			rel := filepath.Clean(filepath.Join(filepath.Dir(filepath.FromSlash(page.name)), filepath.FromSlash(target)))
			if _, err := os.Stat(filepath.Join("..", rel)); err != nil {
				unresolved++
				t.Errorf("%s links %s — no repo file at that path", page.name, target)
			}
		}
	}
	if unresolved > 0 {
		t.Fatalf("%d broken cites or links on the DX1 gate docs surfaces", unresolved)
	}
}
