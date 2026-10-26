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
	"structs"
	"testing"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	"github.com/trishula-dev/trishula/internal/fastpath/celfastpath"
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
			if cel := b.FastPath.CELRules; len(cel) > 0 {
				// TR-196: the compiled CEL-class rows load through the
				// flow object per bundle; the staged rows read back.
				fcoll, err := celfastpath.Instantiate(b)
				if err != nil {
					t.Fatalf("Instantiate(%s) (the flow object): verifier load: %v", name, err)
				}
				defer fcoll.Close()
				if prog := fcoll.Programs["tc_ingress_waf"]; prog == nil {
					t.Fatalf("the loaded flow collection misses tc_ingress_waf: %v", fcoll.Programs)
				}
				fm := fcoll.Maps["fp_rules"]
				if fm == nil {
					t.Fatalf("the loaded flow collection misses fp_rules: %v", fcoll.Maps)
				}
				staged, err := celfastpath.Stage(b)
				if err != nil {
					t.Fatalf("Stage(%s) (cel): %v", name, err)
				}
				frows := map[uint32]celfastpath.CELStage{}
				// The direct reads over the fixed array: every in-bounds
				// seat carries a record (an array lookup never errors), so
				// the enabled byte names the live rows — the kernel's own
				// row-live predicate (the fp walk's enabled gate).
				for idx := uint32(0); idx < fastpath.FastPathCELMaxRules; idx++ {
					var fv fpRuleVal
					if err := fm.Lookup(idx, &fv); err != nil {
						t.Fatalf("fp_rules (%s) lookup row %d: %v", name, idx, err)
					}
					if fv.Enabled == 0 {
						continue // the empty seat; the stage count compares below
					}
					frows[idx] = stagedRowOf(fv, idx)
				}
				if len(frows) != len(staged) {
					t.Fatalf("fp_rules (%s): %d rows, want %d", name, len(frows), len(staged))
				}
				for _, st := range staged {
					got, ok := frows[st.ID]
					if !ok {
						t.Errorf("fp_rules (%s) misses row %d", name, st.ID)
						continue
					}
					if got.Action != st.Action || got.GlobKind != st.GlobKind ||
						got.MethodLen != st.MethodLen || got.PreLen != st.PreLen ||
						got.SufLen != st.SufLen || got.QueryLen != st.QueryLen {
						t.Errorf("fp_rules (%s)[%d] = %+v, want %+v", name, st.ID, got, st)
					}
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

// TestBundleShapeGateCELNegatives reads the CEL-class leg's negative row:
// a duplicated staged id fails Stage with the offending row named,
// kernel-free, before the verifier.
func TestBundleShapeGateCELNegatives(t *testing.T) {
	mustKernel(t)
	b := loadShape(t, "cel_class_2row.json")
	if b.FastPath == nil || len(b.FastPath.CELRules) == 0 {
		t.Fatalf("shape cel_class_2row.json carries no CEL-class leg")
	}
	// The envelope seat count = one. A second in-class rule routes T2 at
	// compile (the envelope gate), so the negative here = the duplicate
	// id reject on the staged set: the second raw rule repeats the seat
	// row's id and Stage rejects kernel-free.
	seat := b.FastPath.CELRules[0]
	b.FastPath.CELRules = append(b.FastPath.CELRules, fastpath.FastPathCELRule{
		ID: seat.ID, Action: fastpath.RouteTemplateActionDrop, Method: "POST",
	})
	staged, err := celfastpath.Stage(b)
	if err == nil {
		t.Fatalf("Stage(duplicate-id cel leg) = %d rows, want a rejection", len(staged))
	}
	if !strings.Contains(err.Error(), "repeats an earlier row") {
		t.Fatalf("err = %v, want the duplicate-id reject row", err)
	}
	coll, err := celfastpath.Instantiate(b)
	if err == nil {
		if coll != nil {
			coll.Close()
		}
		t.Fatal("Instantiate(duplicate-id cel leg) succeeded, want the staged-set rejection")
	}
	if coll != nil {
		coll.Close()
		t.Fatal("Instantiate returned a collection on the failure path")
	}
}

// fpRuleVal mirrors the fp_rules map value (bpf/flow_tc.c's struct
// fp_rule_val; the mirror reads the row truth back on the gate). The
// struct keeps the generated mirror's shape: the struct host layout,
// the declared field order, the pad byte. The sysenc marshal then
// matches the 92-byte kernel record cell by cell.
type fpRuleVal struct {
	_         structs.HostLayout
	Id        uint32
	Enabled   uint8
	Action    uint8
	MethodLen uint8
	GlobKind  uint8
	PreLen    uint8
	SufLen    uint8
	QueryLen  uint8
	Method    [fastpath.FastPathCELMethodMaxBytes]byte
	Pre       [fastpath.FastPathCELGlobPrefixMaxBytes]byte
	Suf       [fastpath.FastPathCELGlobSuffixMaxBytes]byte
	Query     [fastpath.FastPathCELQueryMaxBytes]byte
	_         [1]byte
}

// stagedRowOf renders one read-back row into the staged shape the gate
// compares.
func stagedRowOf(fv fpRuleVal, fk uint32) celfastpath.CELStage {
	return celfastpath.CELStage{
		ID:        fk,
		Action:    fv.Action,
		GlobKind:  fv.GlobKind,
		MethodLen: fv.MethodLen,
		PreLen:    fv.PreLen,
		SufLen:    fv.SufLen,
		QueryLen:  fv.QueryLen,
	}
}
