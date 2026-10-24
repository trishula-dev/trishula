// Package cuegen is the TR-46 (issue #192) derivation layer: the CUE
// packages under cue/ own the definitions, this package materialises the
// derived artefacts from them, and the golden-diff gate rejects hand edits
// to the derived files (the spec's "one definition, many derived artefacts"
// rule).
//
// Derived surfaces (the TR-46 census record, issue #192):
//
//   - cue/seedpack:       rules/cel/seed.yaml + internal/operator/seed_pack.yaml
//   - cue/banconformance: test/ban-conformance/ban_conformance_fixtures.yaml
//   - cue/lab/dx1:        deployment/dx1/manifests/*.yaml
//
// The CRD (manifests/crd/wafpolicy-crd.yaml) is controller-gen-owned. CUE
// carries its validation layer (cue/crd) and vet checks it; this package
// does not write it.
//
// The spec cites: docs/spec.md section 19 (reference implementation,
// declarative artefacts) and section 8.2 (the component map).
package cuegen

import (
	"fmt"
	"os"
	"path/filepath"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
)

// cuePackages are the CUE packages this package builds. Paths are relative
// to the module root.
var cuePackages = []string{
	"./cue/seedpack",
	"./cue/banconformance",
	"./cue/lab/dx1",
	"./cue/crd",
}

// findModuleRoot walks up from dir until it finds the go.mod directory. The
// repo module root also carries the CUE module root (cue.mod).
func findModuleRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if st, statErr := os.Stat(filepath.Join(abs, "go.mod")); statErr == nil && !st.IsDir() {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fmt.Errorf("cuegen: no go.mod found above %s", dir)
		}
		abs = parent
	}
}

// cueBuild loads the named CUE packages against the CUE module root and
// returns one value per package. A load error or a build error fails here,
// so callers never see half-built values.
func cueBuild(root string, pkgs []string) (map[string]cue.Value, error) {
	cfg := &load.Config{Dir: root}
	insts := load.Instances(pkgs, cfg)
	out := make(map[string]cue.Value, len(insts))
	ctx := cuecontext.New()
	for i, inst := range insts {
		if inst.Err != nil {
			return nil, fmt.Errorf("cuegen: load %s: %v", pkgs[i], inst.Err)
		}
		out[pkgs[i]] = ctx.BuildInstance(inst)
	}
	return out, nil
}
