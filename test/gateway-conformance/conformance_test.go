package gatewayconformance

// The lane's own guard tests, written against the spec's contract and honest-delta record
// before the verdict surface existed: the RED watch pins the
// conformance verdicts (TestRunReference-/SecondaryProfileConformance),
// the record/profile pins hold by design (data guards — they gate the
// typed record, not the drive path).
import (
	"errors"
	"sort"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/http2"
)

func TestDeltaRecordPinsTheDeltaTable(t *testing.T) {
	d, err := LoadDelta()
	if err != nil {
		t.Fatalf("LoadDelta: %v", err)
	}
	if got := len(d.ByID); got != 9 {
		t.Fatalf("delta table carries %d rows, want the §10.5 table's 9", got) // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}
	for _, id := range []string{
		"steer-http", "h2c-to-engine", "weighted-canary", "readiness-gated-pools",
		"gateway-tls-terminate", "weight0-fallback-failopen", "extproc-nohop",
		"epp-model-pool", "shield-gateway-independent",
	} {
		if _, ok := d.ByID[id]; !ok {
			t.Fatalf("delta table lost row %q", id)
		}
	}
	r := d.ByID["h2c-to-engine"]
	if r.Leg != LegEngine || r.Degradation != "none" {
		t.Fatalf("h2c-to-engine row: leg %q degradation %q, want engine + none", r.Leg, r.Degradation)
	}
	if d.ByID["shield-gateway-independent"].Leg != LegKernel {
		t.Fatalf("shield row: leg %q, want kernel", d.ByID["shield-gateway-independent"].Leg)
	}
	verifyGw := map[string]bool{}
	for id, row := range d.ByID {
		if !row.PerGatewayVerify {
			continue
		}
		if row.Leg != LegGateway {
			t.Fatalf("row %q carries per-gateway verify on leg %q", id, row.Leg)
		}
		verifyGw[id] = true
	}
	want := []string{"weight0-fallback-failopen", "extproc-nohop", "epp-model-pool"}
	sort.Strings(want)
	if len(verifyGw) != len(want) {
		t.Fatalf("per-gateway verify rows = %v, want exactly %v", verifyGw, want)
	}
	for _, id := range want {
		if !verifyGw[id] {
			t.Fatalf("row %q lost its per-gateway verify marker", id)
		}
	}
}

func TestLoadProfilesCarriesEngineLegCases(t *testing.T) {
	ps := LoadProfiles()
	if len(ps) != 2 {
		t.Fatalf("LoadProfiles built %d profiles, want the reference and the secondary", len(ps))
	}
	roles := map[string]Role{ps[0].ID: ps[0].Role, ps[1].ID: ps[1].Role}
	if roles["ngf"] != RoleReference || roles["envoy-gw"] != RoleSecondary {
		t.Fatalf("profile roles off: %v", roles)
	}
	for _, p := range ps {
		if err := p.Validate(); err != nil {
			t.Fatalf("profile %q: %v", p.ID, err)
		}
		if p.Parity.Name == "" || len(p.Parity.Frames) == 0 {
			t.Fatalf("profile %q lost its parity case", p.ID)
		}
		rows := map[string]bool{}
		for _, c := range p.H2 {
			rows[c.Contract] = true
		}
		if !rows[RowH2CIngress] || !rows[RowGRPCRecognized] {
			t.Fatalf("profile %q: h2c-ingress and grpc-recognized cases both required", p.ID)
		}
	}
	if ps[0].Version != "2.7.2" || ps[1].Version != "1.9.2" {
		t.Fatalf("version pins off: ngf %q envoy-gw %q, want 2.7.2 and 1.9.2", ps[0].Version, ps[1].Version)
	}
}

func TestRunReferenceProfileConformance(t *testing.T) {
	ps := LoadProfiles()
	fs, err := Run(ps[0], NewDrive())
	if err != nil {
		t.Fatalf("Run reference profile: %v", err)
	}
	if len(fs) != 4 {
		t.Fatalf("Run returned %d findings, want 4 rows per profile", len(fs))
	}
	passed := map[string]bool{}
	for _, f := range fs {
		if f.Profile != "ngf" {
			t.Fatalf("finding carries profile %q, want ngf", f.Profile)
		}
		if !ContractRows[f.Row] {
			t.Fatalf("finding names out-of-lane row %q", f.Row)
		}
		if !f.Pass {
			t.Fatalf("row %q case %q: %s", f.Row, f.Case, f.Detail)
		}
		passed[f.Row] = true
	}
	for _, row := range []string{RowSameViewParity, RowH2CIngress, RowGRPCRecognized, RowPlainBackendView} {
		if !passed[row] {
			t.Fatalf("row %q never drove", row)
		}
	}
}

func TestRunSecondaryProfileConformance(t *testing.T) {
	ps := LoadProfiles()
	fs, err := Run(ps[1], NewDrive())
	if err != nil {
		t.Fatalf("Run secondary profile: %v", err)
	}
	if len(fs) != 4 {
		t.Fatalf("Run returned %d findings, want 4 rows per profile", len(fs))
	}
	for _, f := range fs {
		if f.Profile != "envoy-gw" {
			t.Fatalf("finding carries profile %q, want envoy-gw", f.Profile)
		}
		if !f.Pass {
			t.Fatalf("row %q case %q: %s", f.Row, f.Case, f.Detail)
		}
	}
}

func TestRunRejectsMisuse(t *testing.T) {
	ps := LoadProfiles()
	ps[0].H2[0].Contract = "steer-http" // a spec honest-delta gateway-leg row, not a case row
	_, err := Run(ps[0], NewDrive())
	if !errors.Is(err, ErrProfile) {
		t.Fatalf("bound-to-gateway-row misuse: %v, want ErrProfile", err)
	}
	fresh := LoadProfiles()
	_, err = Run(fresh[0], Drive{})
	if !errors.Is(err, ErrDrive) {
		t.Fatalf("nil drive misuse: %v, want ErrDrive", err)
	}
}

// The recognition contract is content-based per TR-15: the lane's
// gRPC case wants the exact same classification the engine surface
// carries (the constant never drifts under the lane unnoticed).
func TestGRPCKindIsTheEngineSurfaceConstant(t *testing.T) {
	if http2.KindGRPC != http2.Kind("grpc") {
		t.Fatalf("KindGRPC = %q, want the engine surface constant grpc", http2.KindGRPC)
	}
}
