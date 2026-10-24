package cuegen

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/encoding/yaml"
)

// Output carries one derived artefact: its repo-relative path and the exact
// bytes the derivation gives it (always newline-terminated).
type Output struct {
	Path  string
	Bytes []byte
}

// Plan derives every TR-46 artefact from the CUE definitions:
//
//   - cue/seedpack:       rules/cel/seed.yaml + internal/operator/seed_pack.yaml
//   - cue/banconformance: test/ban-conformance/ban_conformance_fixtures.yaml
//   - cue/lab/dx1:        deployment/dx1/manifests/<name>.yaml
//
// The CRD (manifests/crd/wafpolicy-crd.yaml) is controller-gen-owned and is
// never written here.
func Plan(root string) ([]Output, error) {
	vals, err := cueBuild(root, cuePackages)
	if err != nil {
		return nil, err
	}

	var outs []Output
	if err := appendSeedPack(&outs, vals["./cue/seedpack"]); err != nil {
		return nil, fmt.Errorf("cuegen: seedpack: %w", err)
	}
	if err := appendBanFixtures(&outs, vals["./cue/banconformance"]); err != nil {
		return nil, fmt.Errorf("cuegen: banconformance: %w", err)
	}
	if err := appendLabManifests(&outs, vals["./cue/lab/dx1"]); err != nil {
		return nil, fmt.Errorf("cuegen: lab dx1: %w", err)
	}
	return outs, nil
}

// Run regenerates every derived artefact in place under root.
func Run(dir string) error {
	root, err := findModuleRoot(dir)
	if err != nil {
		return err
	}
	outs, err := Plan(root)
	if err != nil {
		return err
	}
	for _, o := range outs {
		full := filepath.Join(root, filepath.FromSlash(o.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("cuegen: mkdir for %s: %w", o.Path, err)
		}
		if err := os.WriteFile(full, o.Bytes, 0o644); err != nil {
			return fmt.Errorf("cuegen: write %s: %w", o.Path, err)
		}
	}
	return nil
}

// appendSeedPack derives rules/cel/seed.yaml and internal/operator/seed_pack.yaml
// — both copies carry the same bytes (internal/operator/seedpack_test.go
// guards the identity).
func appendSeedPack(outs *[]Output, pack cue.Value) error {
	header, err := pack.LookupPath(cue.ParsePath("header")).String()
	if err != nil {
		return err
	}
	body, err := documentValue(pack.LookupPath(cue.ParsePath("pack")))
	if err != nil {
		return err
	}
	content := append(commentHeader(header), body...)
	*outs = append(*outs,
		Output{Path: "rules/cel/seed.yaml", Bytes: content},
		Output{Path: "internal/operator/seed_pack.yaml", Bytes: append([]byte(nil), content...)},
	)
	return nil
}

// appendBanFixtures derives test/ban-conformance/ban_conformance_fixtures.yaml.
func appendBanFixtures(outs *[]Output, pkg cue.Value) error {
	header, err := pkg.LookupPath(cue.ParsePath("header")).String()
	if err != nil {
		return err
	}
	body, err := documentValue(pkg.LookupPath(cue.ParsePath("doc")))
	if err != nil {
		return err
	}
	content := append(commentHeader(header), body...)
	*outs = append(*outs, Output{Path: "test/ban-conformance/ban_conformance_fixtures.yaml", Bytes: content})
	return nil
}

// labEntry is one cue/lab/dx1 files entry: the derived file name and its
// definition value.
type labEntry struct {
	name string
	val  cue.Value
}

// appendLabManifests derives deployment/dx1/manifests/<name>.yaml, one file
// per cue/lab/dx1 files entry. The write order is sorted by file name so
// the derivation is deterministic.
func appendLabManifests(outs *[]Output, lab cue.Value) error {
	files := lab.LookupPath(cue.ParsePath("files"))
	it, err := files.Fields()
	if err != nil {
		return err
	}
	var entries []labEntry
	for it.Next() {
		entries = append(entries, labEntry{name: it.Label(), val: it.Value()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	for _, e := range entries {
		header, err := e.val.LookupPath(cue.ParsePath("header")).String()
		if err != nil {
			return fmt.Errorf("%s: %w", e.name, err)
		}
		docs, err := documentStream(e.val.LookupPath(cue.ParsePath("objects")))
		if err != nil {
			return fmt.Errorf("%s: %w", e.name, err)
		}
		content := commentHeader(header)
		for _, d := range docs {
			content = append(content, []byte("---\n")...)
			content = append(content, d...)
		}
		if !bytes.HasSuffix(content, []byte("\n")) {
			content = append(content, '\n')
		}
		*outs = append(*outs, Output{Path: "deployment/dx1/manifests/" + e.name, Bytes: content})
	}
	return nil
}

// documentValue encodes one CUE value as a single YAML document
// (newline-terminated).
func documentValue(v cue.Value) ([]byte, error) {
	b, err := yaml.Encode(v)
	if err != nil {
		return nil, err
	}
	return append(bytes.TrimRight(b, "\n"), '\n'), nil
}

// documentStream encodes a CUE list of objects as a stream of YAML
// documents — one element, one document, each newline-terminated. The
// callers add the "---" document separators.
func documentStream(v cue.Value) ([][]byte, error) {
	list, err := v.List()
	if err != nil {
		return nil, err
	}
	var docs [][]byte
	for list.Next() {
		b, err := documentValue(list.Value())
		if err != nil {
			return nil, err
		}
		docs = append(docs, b)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("the object list is empty")
	}
	return docs, nil
}

// commentHeader normalises a CUE header string into the comment block the
// derived file carries: the header text verbatim, ending with exactly one
// newline.
func commentHeader(header string) []byte {
	return []byte(strings.TrimRight(header, "\n") + "\n")
}
