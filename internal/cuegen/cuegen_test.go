package cuegen

import (
	"os"
	"path/filepath"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"
)

// root returns the repo module root for the test tree (the go.mod
// directory above this package's own directory).
func root(t *testing.T) string {
	t.Helper()
	r, err := findModuleRoot("..")
	if err != nil {
		t.Fatalf("find module root: %v", err)
	}
	return r
}

// TestCUEPackagesValidateConcrete builds every TR-46 CUE package through the
// CUE Go API and validates each value concrete. The data instances must
// satisfy the schemas they carry; this is the `cue vet` semantic through the
// Go API, so the plain go-test path enforces the same rule as the CI gate
// (the TR-46 exit criterion: a structure test consumes the CUE Go API).
func TestCUEPackagesValidateConcrete(t *testing.T) {
	vals, err := cueBuild(root(t), cuePackages)
	if err != nil {
		t.Fatalf("build CUE packages: %v", err)
	}
	for pkg, v := range vals {
		if err := v.Validate(cue.Concrete(true), cue.Final()); err != nil {
			t.Errorf("%s: does not validate concrete: %v", pkg, err)
		}
	}
}

// TestCRDValidationLayer pins the CRD row of the TR-46 census: the CRD stays
// controller-gen-owned, and the cue/crd package is the validation layer CUE
// adds on top. Two checks:
//
//   - the committed CRD (manifests/crd/wafpolicy-crd.yaml, the controller-gen
//     output) unifies with the cue/crd envelope schema #WAFPolicyCRD;
//   - every WAFPolicy CR inside the lab CUE package unifies with the same
//     CUE-layer spec schema (#WAFPolicySpec) the CRD carries.
func TestCRDValidationLayer(t *testing.T) {
	r := root(t)
	vals, err := cueBuild(r, []string{"./cue/crd", "./cue/lab/dx1"})
	if err != nil {
		t.Fatalf("build CUE packages: %v", err)
	}
	crdPkg := vals["./cue/crd"]
	labPkg := vals["./cue/lab/dx1"]

	t.Run("committed-crd-file", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(r, "manifests/crd/wafpolicy-crd.yaml"))
		if err != nil {
			t.Fatalf("read committed CRD: %v", err)
		}
		f, err := yaml.Extract("wafpolicy-crd.yaml", raw)
		if err != nil {
			t.Fatalf("parse committed CRD as YAML: %v", err)
		}
		data := cuecontext.New().BuildFile(f)
		envelope := crdPkg.LookupPath(cue.ParsePath("#WAFPolicyCRD"))
		unified := envelope.Unify(data)
		if err := unified.Validate(cue.Concrete(true)); err != nil {
			t.Fatalf("committed CRD fails the cue/crd validation layer: %v", err)
		}
	})

	t.Run("lab-wafpolicies", func(t *testing.T) {
		specSchema := crdPkg.LookupPath(cue.ParsePath("#WAFPolicySpec"))
		files := labPkg.LookupPath(cue.ParsePath("files"))
		it, err := files.Fields()
		if err != nil {
			t.Fatalf("iterate cue/lab/dx1 files: %v", err)
		}
		sawPolicy := false
		for it.Next() {
			objects := it.Value().LookupPath(cue.ParsePath("objects"))
			list, err := objects.List()
			if err != nil {
				t.Fatalf("%s: objects list: %v", it.Label(), err)
			}
			for list.Next() {
				obj := list.Value()
				kind, err := obj.LookupPath(cue.ParsePath("kind")).String()
				if err != nil || kind != "WAFPolicy" {
					continue
				}
				sawPolicy = true
				spec := obj.LookupPath(cue.ParsePath("spec"))
				unified := specSchema.Unify(spec)
				if err := unified.Validate(cue.Concrete(true)); err != nil {
					t.Errorf("%s: WAFPolicy spec fails the cue/crd validation layer: %v", it.Label(), err)
				}
			}
		}
		if !sawPolicy {
			t.Fatal("the lab CUE package carries no WAFPolicy objects; the CRD-schema check ran against nothing")
		}
	})
}
