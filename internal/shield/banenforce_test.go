package shield

// TR-10 (issue #10) RED suite — the ScoredWindowBan → kernel bans_v4
// enforcement leg. Portables here: the bans_v4 wire contract, the wire
// reason codes, the engine→kernel adapter (BanEnforcer) and the JSONL
// evidence sink. The kernel-truth gate is the in-VM E2E (test/banenforce,
// tag ban_e2e); RED here = these symbols do not exist yet (TR-10's GREEN
// lands them).
import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// Wire constants under test (the §13.3 tier's reason name/code, the
// TR-03 legacy convention for unscored bans, and the C struct sizes of
// bpf/ban_xdp.c: key = be32 saddr + u8 family + u8 key_class + u16 pad;
// value = u64 ban_until_ms + u16 score + u16 reason_code + u32 pad).
const (
	wantReasonName        = "scored-window"
	wantReasonCode uint16 = 1300
	wantLegacyCode uint16 = 0
	wantKeySize           = 8
	wantValSize           = 16
)

func TestReasonCodesWire(t *testing.T) {
	code, err := ReasonCode(wantReasonName)
	if err != nil || code != wantReasonCode {
		t.Fatalf("ReasonCode(%q) = %d, %v; want %d", wantReasonName, code, err, wantReasonCode)
	}
	if code, err := ReasonCode(""); err != nil || code != wantLegacyCode {
		t.Fatalf("ReasonCode(\"\") = %d, %v; want %d (TR-03 legacy: unscored bans)", code, err, wantLegacyCode)
	}
	if _, err := ReasonCode("not-a-reason"); err == nil {
		t.Fatal("unknown reason accepted — the wire code space stays a known enum")
	}
}

func TestBansV4WireContract(t *testing.T) {
	if got := binary.Size(BansV4Key{}); got != wantKeySize {
		t.Fatalf("BansV4Key marshals to %d bytes, want %d", got, wantKeySize)
	}
	if got := binary.Size(BansV4Val{}); got != wantValSize {
		t.Fatalf("BansV4Val marshals to %d bytes, want %d", got, wantValSize)
	}
	k, err := BansV4KeyFromIP(netip.MustParseAddr("10.66.0.66"))
	if err != nil {
		t.Fatalf("BansV4KeyFromIP: %v", err)
	}
	if got := binary.BigEndian.Uint32(k.SAddr[:]); got != 0x0a420042 {
		t.Fatalf("SAddr = %#x, want network-order 0x0a420042", got)
	}
	if k.Family != FamilyV4 || k.KeyClass != KeyClassIP {
		t.Fatalf("loader discipline fields: %+v", k)
	}
	if _, err := BansV4KeyFromIP(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("bans_v4 is IPv4-keyed; a v6 key must be refused")
	}
}

// The adapter: a would-ban the ENGINE emits must land in the kernel map
// (the publish) and then in the evidence stream (§13.5: every ban decision
// carries its record; an unpublished ban claims kernel state that does
// not exist).
func TestBanEnforcerPublishesAndRecords(t *testing.T) {
	const nowNs = 42_000_000_000_000 // 42_000_000 ms on the kernel clock
	pub := &stubBansV4{bans: map[[4]byte]BansV4Val{}}
	sink := NewJSONLEvidenceSink()
	bx := NewBanEnforcer(pub, sink)
	bx.clockNs = func() (uint64, error) { return nowNs, nil }

	eng := rateban.BanEvidence{
		Key: "10.66.0.66", Verdict: "would-ban", Mode: "shadow", Tier: "scored-window",
		Score: 12.34, Threshold: 10, AtSec: 500, UntilSec: 1100,
		Recidivism: 1, BantimeSec: 600,
		ReasonCodes: []string{"rateBreach"},
		Events:      []rateban.EvidenceEvent{{Kind: "rateBreach", Weight: 3, AtSec: 499}},
	}
	if err := bx.Record(eng); err != nil {
		t.Fatalf("Record: %v", err)
	}
	v, ok := pub.bans[[4]byte{10, 66, 0, 66}]
	if !ok {
		t.Fatal("would-ban never published to bans_v4")
	}
	// until = publish-now (kernel ms) + the engine's remaining window.
	wantUntil := uint64(42_000_000) + 600*1000
	if v.BanUntilMs != wantUntil {
		t.Fatalf("BanUntilMs = %d, want %d (publish-now + window)", v.BanUntilMs, wantUntil)
	}
	if wantScore := uint16(12.34*100 + 0.5); v.Score != wantScore {
		t.Fatalf("Score u16 = %d, want %d (score × 100)", v.Score, wantScore)
	}
	if v.ReasonCode != wantReasonCode {
		t.Fatalf("ReasonCode = %d, want %d", v.ReasonCode, wantReasonCode)
	}

	recs := sink.Records()
	if len(recs) != 1 {
		t.Fatalf("evidence records = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.Verdict != "ban" || r.SourceIP != "10.66.0.66" || !r.Published {
		t.Fatalf("record enrichment: %+v", r)
	}
	// The R11 account must survive the wire hop verbatim (§13.5).
	if r.Score != 12.34 || r.Threshold != 10 || r.WindowSec != 600 ||
		r.UntilSec != 1100 || r.Recidivism != 1 || r.BantimeSec != 600 {
		t.Fatalf("R11 fields lost: %+v", r)
	}
	if r.UntilMS != wantUntil {
		t.Fatalf("record UntilMS = %d, want %d", r.UntilMS, wantUntil)
	}
	if len(r.ReasonCodes) != 1 || r.ReasonCodes[0] != "rateBreach" {
		t.Fatalf("reasonCodes lost: %+v", r.ReasonCodes)
	}
	if len(r.Events) != 1 || r.Events[0].Kind != "rateBreach" || r.Events[0].Weight != 3 {
		t.Fatalf("events trajectory lost: %+v", r.Events)
	}
}

func TestBanEnforcerReconcileLiftsExpired(t *testing.T) {
	pub := &stubBansV4{bans: map[[4]byte]BansV4Val{}}
	bx := NewBanEnforcer(pub, NewJSONLEvidenceSink())
	bx.clockNs = func() (uint64, error) { return 1_000_000_000, nil } // 1000 ms
	eng := rateban.BanEvidence{
		Key: "10.66.0.66", Verdict: "would-ban", Mode: "shadow", Tier: "scored-window",
		Score: 11, Threshold: 10, AtSec: 500, UntilSec: 1100, Recidivism: 0, BantimeSec: 600,
	}
	if err := bx.Record(eng); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if lifted := bx.Reconcile(1099); lifted != 0 {
		t.Fatalf("pre-expiry reconcile lifted %d", lifted)
	}
	if _, ok := pub.bans[[4]byte{10, 66, 0, 66}]; !ok {
		t.Fatal("pre-expiry reconcile deleted a live ban")
	}
	// Expiry parity with the engine (BanVal.Expired semantics): now >=
	// until means the ban is over.
	if lifted := bx.Reconcile(1100); lifted != 1 {
		t.Fatalf("post-expiry (now >= until) lifted %d, want 1", lifted)
	}
	if _, ok := pub.bans[[4]byte{10, 66, 0, 66}]; ok {
		t.Fatal("expired ban survived the kernel table")
	}
}

func TestBanEnforcerSurfacesPublishFailure(t *testing.T) {
	pub := &stubBansV4{bans: map[[4]byte]BansV4Val{}}
	sink := NewJSONLEvidenceSink()
	bx := NewBanEnforcer(pub, sink)
	bx.clockNs = func() (uint64, error) { return 1_000, nil }

	err := bx.Record(rateban.BanEvidence{
		Key: "not-an-ip", Verdict: "would-ban", Mode: "shadow", Tier: "scored-window",
		Score: 11, Threshold: 10, AtSec: 5, UntilSec: 7, Recidivism: 0, BantimeSec: 2,
	})
	if err == nil {
		t.Fatal("unpublishable key accepted")
	}
	recs := sink.Records()
	if len(recs) != 1 || recs[0].Published || recs[0].PublishErr == "" {
		t.Fatalf("failed publish must be evidenced with publishErr: %+v", recs)
	}
}

func TestJSONLEvidenceSinkFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ban_evidence.jsonl")
	sink := NewJSONLEvidenceSink()
	if err := sink.AppendFile(path); err != nil {
		t.Fatalf("AppendFile: %v", err)
	}
	pub := &stubBansV4{bans: map[[4]byte]BansV4Val{}}
	bx := NewBanEnforcer(pub, sink)
	bx.clockNs = func() (uint64, error) { return 2_000_000_000, nil } // 2000 ms

	ban := rateban.BanEvidence{
		Key: "10.66.0.9", Verdict: "would-ban", Mode: "shadow", Tier: "scored-window",
		Score: 12, Threshold: 10, AtSec: 500, UntilSec: 1101, Recidivism: 0, BantimeSec: 601,
		ReasonCodes: []string{"rateBreach"},
	}
	bad := rateban.BanEvidence{
		Key: "not-an-ip", Verdict: "would-ban", Mode: "shadow", Tier: "scored-window",
		Score: 12, Threshold: 10, AtSec: 500, UntilSec: 1101, Recidivism: 0, BantimeSec: 601,
	}
	if err := bx.Record(ban); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := bx.Record(bad); err == nil {
		t.Fatal("unpublishable key accepted")
	}
	if got := sink.Count(); got != 2 {
		t.Fatalf("in-memory records = %d, want 2", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("file lines = %d, want 2 (append-only, one per record)", len(lines))
	}
	var rec BanRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line is not JSON: %v\n%s", err, lines[0])
	}
	if !rec.Published || rec.Verdict != "ban" || rec.SourceIP != "10.66.0.9" {
		t.Fatalf("record invariants: %+v", rec)
	}
	if got, want := rec.UntilMS, uint64(2_000_000+601*1000); got != want {
		t.Fatalf("UntilMS = %d, want %d", got, want)
	}
	t.Logf("evidence line: %s", lines[0])
}

// stubBansV4 is the MapPublisher fake (tests stub the kernel; the in-VM
// e2e exercises the real maps).
type stubBansV4 struct {
	mu      sync.Mutex
	bans    map[[4]byte]BansV4Val
	deleted [][4]byte
}

func (s *stubBansV4) PutBansV4(k BansV4Key, v BansV4Val) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans[k.SAddr] = v
	return nil
}

func (s *stubBansV4) DeleteBansV4(k BansV4Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bans, k.SAddr)
	s.deleted = append(s.deleted, k.SAddr)
	return nil
}
