package docs

import (
	"regexp"
	"testing"
)

// TestPRDStageSketchDualStackKeys fails while the §19.1 stage sketches
// declare ban_key/verdict_key/flow_key with a bare __u32 address in a
// design that is explicitly dual-stack (§9.3 acl4/acl6, §9.2 "IPv4/IPv6",
// §13.3 /24-vs-/48 prefix escalation): a 32-bit key cannot hold an IPv6
// address and a /48 prefix would alias its contained hosts. Defect #62.
//
// Contract: the three key structs carry a family-discriminated address
// union plus an explicit family member — not a bare u32 addr.
func TestPRDStageSketchDualStackKeys(t *testing.T) {
	prd := readPRD(t)
	s191 := prdSection(prd, "19.1")
	if s191 == "" {
		t.Fatal("§19.1 not found in PRD.md")
	}
	blocks := cBlocks(s191)
	if len(blocks) == 0 {
		t.Fatal("no ```c blocks found in §19.1")
	}
	reBare := regexp.MustCompile(`__u32\s+\w*(addr|saddr|daddr)`)
	reUnion := regexp.MustCompile(`(?s)union\s*\{`)
	reFamily := regexp.MustCompile(`(?m)^\s*__u8\s+family\s*;`)
	reV6 := regexp.MustCompile(`v6\[16\]|in6_addr`)
	for _, name := range []string{"ban_key", "verdict_key", "flow_key"} {
		t.Run(name, func(t *testing.T) {
			body, ok := structBody(blocks, name)
			if !ok {
				t.Fatalf("struct %s not found in §19.1 ```c blocks", name)
			}
			if reBare.MatchString(body) {
				t.Fatalf("%s declares a bare __u32 address; want a family-discriminated union (defect #62):\n%s", name, body)
			}
			if !reUnion.MatchString(body) {
				t.Fatalf("%s has no v4/v6 address union\n%s", name, body)
			}
			if !reFamily.MatchString(body) {
				t.Fatalf("%s has no explicit family member\n%s", name, body)
			}
			if !reV6.MatchString(body) {
				t.Fatalf("%s union lacks a 16-byte IPv6 arm\n%s", name, body)
			}
		})
	}
}

// prdSection returns the body of the numbered "### <num> " section
// (heading line inclusive, up to the next same-level "### " heading).
func prdSection(doc, num string) string {
	start := regexp.MustCompile(`(?m)^### ` + regexp.QuoteMeta(num) + ` `)
	loc := start.FindStringIndex(doc)
	if loc == nil {
		return ""
	}
	rest := doc[loc[0]:]
	next := regexp.MustCompile(`(?m)^### `)
	if nl := next.FindStringIndex(rest[1:]); nl != nil {
		rest = rest[:nl[1]]
	}
	return rest
}

// cBlocks returns every fenced ```c block body in doc order.
func cBlocks(doc string) []string {
	re := regexp.MustCompile("(?s)```c\n(.*?)```")
	ms := re.FindAllStringSubmatch(doc, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	return out
}

// structBody extracts the body of `struct NAME { ... }` with brace
// counting (lazy regexes stop at the first nested union's close brace).
func structBody(blocks []string, name string) (string, bool) {
	re := regexp.MustCompile(`(?s)struct\s+` + regexp.QuoteMeta(name) + `\s*\{`)
	for _, b := range blocks {
		loc := re.FindStringSubmatchIndex(b)
		if loc == nil {
			continue
		}
		i := loc[1] // just past the opening brace
		depth := 1
		for ; i < len(b) && depth > 0; i++ {
			switch b[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		return b[loc[1] : i-1], true
	}
	return "", false
}
