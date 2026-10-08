package shield

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// SourceSpec is the parsed contract of bpf/shield_xdp.c: the map
// declarations and the SEC entrypoints it actually defines.
type SourceSpec struct {
	Maps     []MapSpec
	Programs []string
}

// Map returns the spec for name (test helper).
func (s SourceSpec) Map(t interface{ Fatalf(string, ...interface{}) }, name string) MapSpec {
	for _, m := range s.Maps {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("map %q not in source spec", name)
	return MapSpec{}
}

// HasProgram reports whether the source defines the named entrypoint.
func (s SourceSpec) HasProgram(sec string) bool {
	for _, p := range s.Programs {
		if p == sec {
			return true
		}
	}
	return false
}

// SpecFromSource parses bpf/shield_xdp.c and returns its map/program
// contract. Source-level (not object-level): the contract holds without a
// Linux host; the object-level assert is the attach test.
func SpecFromSource(t *testing.T, path string) SourceSpec {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)
	spec := SourceSpec{}

	// Maps: struct { __uint(type, BPF_MAP_TYPE_X); __uint(max_entries, N);
	//   __type(key, K); __type(value, V); } NAME SEC(".maps");
	// The §19.1 sketch writes type/max_entries as __uint declarations in
	// any order; key/value types are captured for kind cross-checks.
	mapRe := regexp.MustCompile(`(?s)\}\s+(\w+)\s+SEC\("\.maps"\)?;`)
	blockRe := regexp.MustCompile(`(?s)struct\s*\{(.*?)\}\s*(\w+)\s*SEC\("\.maps"\);`)
	for _, m := range blockRe.FindAllStringSubmatch(src, -1) {
		body, name := m[1], m[2]
		ms := MapSpec{Name: name}
		if kind := regexp.MustCompile(`BPF_MAP_TYPE_(\w+)`).FindStringSubmatch(body); kind != nil {
			ms.Kind = strings.ToLower(kind[1])
		}
		if me := regexp.MustCompile(`max_entries,\s*(.+?)\)`).FindStringSubmatch(body); me != nil {
			expr := strings.TrimSpace(me[1])
			expr = strings.ReplaceAll(expr, " ", "")
			n, err := evalShift(expr)
			if err != nil {
				t.Fatalf("map %s max_entries %q: %v", name, expr, err)
			}
			ms.MaxEntries = n
		}
		spec.Maps = append(spec.Maps, ms)
	}
	_ = mapRe

	// Programs: SEC("xdp") / SEC("tc") before function defs.
	progRe := regexp.MustCompile(`SEC\("(\w+)"\)\s*\n\s*(?:int|__always_inline)`)
	for _, m := range progRe.FindAllStringSubmatch(src, -1) {
		spec.Programs = append(spec.Programs, m[1])
	}
	return spec
}

// evalShift evaluates `1 << N` / literal / sum-of-shifts (§19.1 style).
func evalShift(expr string) (uint32, error) {
	if !strings.Contains(expr, "<<") {
		v, err := strconv.ParseUint(expr, 0, 32)
		if err != nil {
			return 0, err
		}
		return uint32(v), nil
	}
	total := uint64(0)
	for _, part := range strings.Split(expr, "+") {
		p := strings.TrimSpace(part)
		f := strings.SplitN(p, "<<", 2)
		base, err := strconv.ParseUint(strings.TrimSpace(f[0]), 0, 64)
		if err != nil {
			return 0, err
		}
		shift, err := strconv.ParseUint(strings.TrimSpace(f[1]), 0, 6)
		if err != nil {
			return 0, err
		}
		total += base << shift
	}
	return uint32(total), nil
}
