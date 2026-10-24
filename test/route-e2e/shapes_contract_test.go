package routee2e

// The kernel-free companion of the per-bundle load gate (TR-40c, issue
// #189, child of TR-40 #52). Every committed bundle shape walks the
// compile pathway without a kernel: the wire gate loads the shape, the
// staging re-checks the template bounds, and a shape without a kernel leg
// never reaches the loader. The verifier load per bundle rides the tagged
// e2e file (e2e_shapes_linux_test.go). Host CI stays kernel-free.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	"github.com/trishula-dev/trishula/internal/fastpath/routetemplate"
	"github.com/trishula-dev/trishula/internal/operator"
)

// shapesPath points at the committed bundle shapes (the operator compile
// surface's census: internal/operator/testdata/bundle-shapes).
const shapesPath = "../../internal/operator/testdata/bundle-shapes"

// shapesDir lists the committed bundle shapes, sorted. The gate fails on
// an empty set: a gate over no shapes proves nothing.
func shapesDir(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(shapesPath)
	if err != nil {
		t.Fatalf("read the committed bundle shapes: %v", err)
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Fatal("the committed bundle-shape set is empty; the gate needs shapes")
	}
	sort.Strings(names)
	return names
}

// loadShape decodes one committed shape into a bundle.
func loadShape(t *testing.T, name string) *operator.Bundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(shapesPath, name))
	if err != nil {
		t.Fatalf("read shape %s: %v", name, err)
	}
	var b operator.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode shape %s: %v", name, err)
	}
	return &b
}

// TestBundleShapesContract walks every committed bundle shape kernel-free:
// the wire gate loads each shape, staging matches the wire, and a shape
// without a kernel leg stays out of the loader.
func TestBundleShapesContract(t *testing.T) {
	for _, name := range shapesDir(t) {
		t.Run(name, func(t *testing.T) {
			b := loadShape(t, name)
			if _, err := operator.Load(*b); err != nil {
				t.Fatalf("wire gate: Load(%s): %v", name, err)
			}
			staged, err := routetemplate.Stage(b)
			if b.FastPath == nil {
				if err == nil || err.Error() != routetemplate.ErrNoKernelLeg.Error() {
					t.Fatalf("Stage(%s): err = %v, want ErrNoKernelLeg", name, err)
				}
				for field := range b.Split {
					if strings.HasPrefix(field, "spec.routes[]") {
						t.Errorf("kernel-free shape %s split carries %q with a kernel verdict", name, field)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Stage(%s): %v", name, err)
			}
			if len(staged) != len(b.FastPath.Routes) {
				t.Fatalf("Stage(%s): %d staged rows, want %d", name, len(staged), len(b.FastPath.Routes))
			}
			for i, r := range b.FastPath.Routes {
				want := uint32(len(r.Prefix)) * 8
				s := staged[i]
				if s.PrefixLenBits != want || string(s.Prefix[:len(r.Prefix)]) != r.Prefix || s.Action != r.Action || s.ID != uint32(i) {
					t.Errorf("Stage(%s): row %d = %+v, want %q, %d bits, action %d, id %d", name, i, s, r.Prefix, want, r.Action, i)
				}
			}
			for _, field := range []string{"spec.routes[].prefix", "spec.routes[].action"} {
				if got := b.Split[field]; got != fastpath.VerdictKernel.String() {
					t.Errorf("shape %s split[%s] = %q, want %q", name, field, got, fastpath.VerdictKernel.String())
				}
			}
		})
	}
}
