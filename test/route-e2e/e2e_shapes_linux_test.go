//go:build linux

package routee2e

// TR-40c (issue #189, child of TR-40 #52): the per-bundle verifier load
// gate. The gate walks every committed bundle shape and loads each one
// through the kernel verifier: operator.Load, then routetemplate.Instantiate
// → one verifier-accepted collection per bundle. The kernel gate mirrors
// the residue posture (test/residue-e2e): root on Linux, BTF present,
// ROUTE_E2E_REQUIRED=1 turns every environment skip into a failure. Host
// CI stays kernel-free; the kernel-free walk rides shapes_contract_test.go.
//
//	sudo env PATH="$PATH" HOME="$HOME" ROUTE_E2E_REQUIRED=1 \
//	  go test -tags route_e2e -v ./test/route-e2e/

import (
	"strings"
	"testing"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	"github.com/trishula-dev/trishula/internal/fastpath/routetemplate"
	"github.com/trishula-dev/trishula/internal/operator"
)

// TestBundleShapeLoadGate loads every committed bundle shape through the
// kernel verifier, one collection per bundle. The staged map rows read
// back per shape: the row count matches the wire, and every row keeps its
// action code and policy-order id.
func TestBundleShapeLoadGate(t *testing.T) {
	mustKernel(t)
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
				coll, err := routetemplate.Instantiate(b)
				if coll != nil {
					t.Fatalf("Instantiate(%s): a kernel-free shape produced a collection", name)
				}
				if err == nil || err.Error() != routetemplate.ErrNoKernelLeg.Error() {
					t.Fatalf("Instantiate(%s): err = %v, want ErrNoKernelLeg", name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Stage(%s): %v", name, err)
			}
			coll, err := routetemplate.Instantiate(b)
			if err != nil {
				t.Fatalf("Instantiate(%s): verifier load: %v", name, err)
			}
			defer coll.Close()
			if prog := coll.Programs["route_mark"]; prog == nil {
				t.Fatalf("the loaded collection misses route_mark: %v", coll.Programs)
			}
			m := coll.Maps["route_marks"]
			if m == nil {
				t.Fatalf("the loaded collection misses route_marks: %v", coll.Maps)
			}
			rows := map[string]routeVal{}
			var k routeKey
			var v routeVal
			it := m.Iterate()
			for it.Next(&k, &v) {
				rows[string(k.Prefix[:k.Prefixlen/8])] = v
			}
			if err := it.Err(); err != nil {
				t.Fatalf("iterate route_marks (%s): %v", name, err)
			}
			if len(rows) != len(staged) {
				t.Fatalf("route_marks (%s): %d rows, want %d: %v", name, len(rows), len(staged), rows)
			}
			for i, r := range b.FastPath.Routes {
				got, ok := rows[r.Prefix]
				if !ok {
					t.Errorf("route_marks (%s) misses row %s", name, r.Prefix)
					continue
				}
				if got.Action != r.Action || got.ID != uint32(i) {
					t.Errorf("route_marks (%s)[%s] = action %d id %d, want action %d id %d", name, r.Prefix, got.Action, got.ID, r.Action, i)
				}
			}
		})
	}
}

// TestBundleShapeGateNegatives proves the gate's negative row on the
// kernel CI job: an oversized bundle fails with the offending cell named,
// the rejection fires before the verifier, and no collection exists on the
// failure path.
func TestBundleShapeGateNegatives(t *testing.T) {
	mustKernel(t)
	b := loadShape(t, "route_class_2row.json")
	if b.FastPath == nil {
		t.Fatalf("shape route_class_2row.json carries no kernel leg")
	}
	for _, c := range []string{"p", "q", "r", "s", "t", "u", "v"} {
		b.FastPath.Routes = append(b.FastPath.Routes, operator.FastPathRoute{Prefix: "/gate/" + c, Action: fastpath.RouteTemplateActionDrop})
	}
	coll, err := routetemplate.Instantiate(b)
	if err == nil {
		if coll != nil {
			coll.Close()
		}
		t.Fatal("Instantiate(9-row leg) succeeded, want the row-bound rejection")
	}
	if coll != nil {
		coll.Close()
		t.Fatal("Instantiate returned a collection on the failure path")
	}
	if !strings.Contains(err.Error(), "spec.routes carries 9 rows; the template bound is 8 rows") {
		t.Fatalf("err = %v, want the offending cell named", err)
	}
	if strings.Contains(err.Error(), "verifier") {
		t.Fatal("the failure names the verifier; the bound rejects kernel-free, before the load")
	}
}
