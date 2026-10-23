package attest

// The TR-81 verifier contract, tested in-package against injected
// surfaces: no test rides the network. The fixtures stand in for the
// release-assets surface and its attestation store (the live adapters in
// cmd/attest-verify hold the GitHub wire forms). Two synthetic digests
// stand in for the rc1-class asset set. No existing table test carried
// this contract: the package is new, so these are new test functions.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var (
	// assetSHA stands in for a release-asset digest.
	assetSHA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// otherSHA stands in for a different digest on the same release.
	otherSHA = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func mustStatementJSON(t *testing.T, st map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement fixture: %v", err)
	}
	return raw
}

// bundleFor builds one Sigstore bundle object in the wire shape the
// attestations REST surface returns: mediaType + verificationMaterial with
// a tlog entry + dsseEnvelope over the base64 in-toto payload.
func bundleFor(t *testing.T, st map[string]any) Bundle {
	t.Helper()
	payload := base64.StdEncoding.EncodeToString(mustStatementJSON(t, st))
	doc := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"tlogEntries": []any{map[string]any{"logIndex": "1"}},
		},
		"dsseEnvelope": map[string]any{
			"payloadType": "application/vnd.in-toto+json",
			"payload":     payload,
			"signatures":  []any{map[string]any{"sig": "fake-sig"}},
		},
	}
	return Bundle(mustStatementJSON(t, doc))
}

func provenanceStatement(digests []string, builder string) map[string]any {
	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjectsFor(digests),
		"predicateType": PredProvenance,
		"predicate": map[string]any{
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builder},
			},
		},
	}
}

func sbomStatement(digests []string) map[string]any {
	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       subjectsFor(digests),
		"predicateType": PredSBOM,
		"predicate":     map[string]any{"data": map[string]any{"spdxVersion": "SPDX-2.3"}},
	}
}

// subjectsFor builds the statement's subject list: one named subject per
// digest, in order.
func subjectsFor(digests []string) []any {
	subjects := make([]any, 0, len(digests))
	for i, d := range digests {
		subjects = append(subjects, map[string]any{
			"name":   fmt.Sprintf("asset-%02d", i),
			"digest": map[string]any{"sha256": strings.TrimPrefix(d, "sha256:")},
		})
	}
	return subjects
}

type stubLister struct{ assets []AssetSpec }

func (s stubLister) Assets(string) ([]AssetSpec, error) { return s.assets, nil }

type stubListerErr struct{ err error }

func (s stubListerErr) Assets(string) ([]AssetSpec, error) { return nil, s.err }

type stubFetcher struct {
	bundles map[string][]Bundle
	err     error
}

func (s stubFetcher) Bundles(digest string) ([]Bundle, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.bundles[digest], nil
}

func verifierOf(assets []AssetSpec, bundles map[string][]Bundle) *Verifier {
	return &Verifier{
		List:          stubLister{assets: assets},
		Fetch:         stubFetcher{bundles: bundles},
		BuilderPrefix: "https://github.com/trishula-dev/trishula/",
	}
}

func TestDecodeStatementCarriesTheWireFields(t *testing.T) {
	st, err := DecodeStatement(bundleFor(t, provenanceStatement([]string{assetSHA},
		"https://github.com/trishula-dev/trishula/.github/workflows/release-attest.yml@refs/heads/main")))
	if err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if st.PredicateType != PredProvenance {
		t.Errorf("predicate type %q, want %q", st.PredicateType, PredProvenance)
	}
	if got := st.SubjectDigests; len(got) != 1 || got[0] != assetSHA {
		t.Errorf("subject digests %v, want [%s]", got, assetSHA)
	}
	if !strings.HasPrefix(st.Builder, "https://github.com/trishula-dev/trishula/") {
		t.Errorf("builder id %q carries no repository identity", st.Builder)
	}
}

func TestDecodeStatementRejectsMalformedBundles(t *testing.T) {
	malformed := []Bundle{
		Bundle("not-base64-content!"),
		Bundle([]byte(`{"mediaType": "x"}`)),
		Bundle([]byte(`{"dsseEnvelope": {"payloadType": "wrong/type", "payload": "", "signatures": []}}`)),
	}
	for _, b := range malformed {
		if _, err := DecodeStatement(b); err == nil {
			t.Errorf("bundle %q decoded with no error; the contract rejects a malformed bundle", b)
		}
	}
}

func TestDecoderCollectsEverySubjectDigest(t *testing.T) {
	st := provenanceStatement([]string{assetSHA, otherSHA}, "b")
	decoded, err := DecodeStatement(bundleFor(t, st))
	if err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if got := decoded.SubjectDigests; len(got) != 2 || got[0] != assetSHA || got[1] != otherSHA {
		t.Errorf("subject digests %v, want every subject in order", got)
	}
}

func TestDecoderRejectsStatementWithoutSubjects(t *testing.T) {
	st := provenanceStatement([]string{assetSHA}, "b")
	delete(st, "subject")
	if _, err := DecodeStatement(bundleFor(t, st)); err == nil {
		t.Error("statement with no subject decoded with no error; the contract rejects it")
	}
}

func TestVerifierRejectsReleaseWithoutAttestations(t *testing.T) {
	assets := []AssetSpec{
		{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA},
		{Name: "checksums.txt", SHA256: otherSHA},
	}
	results := verifierOf(assets, map[string][]Bundle{}).Verify("2026.01-rc1")
	if len(results) != len(assets) {
		t.Fatalf("Verify() returned %d results, want %d (one verdict per release asset)", len(results), len(assets))
	}
	for _, r := range results {
		if r.Status != StatusReject {
			t.Errorf("asset %s: status %q, want %q — an unattested release surface is the RED case", r.Asset.Name, r.Status, StatusReject)
		}
		joined := strings.Join(r.Reasons, "; ")
		if !strings.Contains(joined, "https://slsa.dev/provenance/v1") || !strings.Contains(joined, "https://spdx.dev/Document/v2.3") {
			t.Errorf("asset %s: reasons %v carry no missing-attestation marker", r.Asset.Name, r.Reasons)
		}
	}
}

func TestVerifierAcceptsFullyAttestedRelease(t *testing.T) {
	assets := []AssetSpec{
		{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA},
		{Name: "checksums.txt", SHA256: otherSHA},
	}
	localBuilder := "https://github.com/trishula-dev/trishula/.github/workflows/release-attest.yml@refs/heads/main"
	bundles := map[string][]Bundle{
		assetSHA: {bundleFor(t, provenanceStatement([]string{assetSHA}, localBuilder)), bundleFor(t, sbomStatement([]string{assetSHA}))},
		otherSHA: {bundleFor(t, provenanceStatement([]string{otherSHA}, localBuilder)), bundleFor(t, sbomStatement([]string{otherSHA}))},
	}
	results := verifierOf(assets, bundles).Verify("2026.01-rc2")
	if len(results) != len(assets) {
		t.Fatalf("Verify() returned %d results, want %d", len(results), len(assets))
	}
	for _, r := range results {
		if r.Status != StatusPass {
			t.Errorf("asset %s: status %q with reasons %v, want %q", r.Asset.Name, r.Status, r.Reasons, StatusPass)
		}
		if !r.Provenance || !r.SBOM {
			t.Errorf("asset %s: provenance=%v sbom=%v, want the asset bound by both attestations", r.Asset.Name, r.Provenance, r.SBOM)
		}
	}
}

func TestVerifierAcceptsTheMultiSubjectReleaseStatement(t *testing.T) {
	// The released attest statements carry every release asset in one
	// subject list; the verifier accepts the asset set from a single
	// statement pair.
	assets := []AssetSpec{
		{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA},
		{Name: "checksums.txt", SHA256: otherSHA},
	}
	localBuilder := "https://github.com/trishula-dev/trishula/.github/workflows/release-attest.yml@refs/heads/main"
	digests := []string{assetSHA, otherSHA}
	bundles := map[string][]Bundle{
		assetSHA: {bundleFor(t, provenanceStatement(digests, localBuilder)), bundleFor(t, sbomStatement(digests))},
		otherSHA: {bundleFor(t, provenanceStatement(digests, localBuilder)), bundleFor(t, sbomStatement(digests))},
	}
	results := verifierOf(assets, bundles).Verify("2026.01-rc2")
	if len(results) != len(assets) {
		t.Fatalf("Verify() returned %d results, want %d", len(results), len(assets))
	}
	for _, r := range results {
		if r.Status != StatusPass || !r.Provenance || !r.SBOM {
			t.Errorf("asset %s: status %q provenance=%v sbom=%v with reasons %v, want both statements bound from the one subject list", r.Asset.Name, r.Status, r.Provenance, r.SBOM, r.Reasons)
		}
	}
}

func TestVerifierRejectsSubjectDigestMismatch(t *testing.T) {
	// The bundle fetch keys on the asset digest, but both statements
	// inside carry a different subject: the binding is broken.
	wrong := map[string][]Bundle{
		assetSHA: {bundleFor(t, provenanceStatement([]string{otherSHA}, "https://github.com/trishula-dev/trishula/.github/workflows/release-attest.yml@refs/heads/main")),
			bundleFor(t, sbomStatement([]string{otherSHA}))},
	}
	results := verifierOf([]AssetSpec{{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA}}, wrong).Verify("2026.01-rc1")
	if len(results) != 1 {
		t.Fatalf("Verify() returned %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusReject {
		t.Errorf("status %q, want %q for a statement bound to a foreign digest", r.Status, StatusReject)
	}
	if len(r.Reasons) == 0 || !strings.Contains(strings.Join(r.Reasons, "; "), otherSHA) {
		t.Errorf("reasons %v carry no mismatch marker that names the offending digest %s", r.Reasons, otherSHA)
	}
}

func TestVerifierRejectsForeignBuilder(t *testing.T) {
	bundles := map[string][]Bundle{
		assetSHA: {bundleFor(t, provenanceStatement([]string{assetSHA}, "https://github.com/other-fork/evil/.github/workflows/attest.yml@refs/heads/main")),
			bundleFor(t, sbomStatement([]string{assetSHA}))},
	}
	results := verifierOf([]AssetSpec{{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA}}, bundles).Verify("2026.01-rc1")
	if len(results) != 1 {
		t.Fatalf("Verify() returned %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusReject {
		t.Errorf("status %q, want %q for a provenance statement built outside the repository identity", r.Status, StatusReject)
	}
	if !r.SBOM {
		t.Errorf("sbom verdict %v, want true — the SBOM attestation stays bound on its own surface", r.SBOM)
	}
	for _, reason := range r.Reasons {
		if strings.Contains(reason, "other-fork") {
			return
		}
	}
	t.Errorf("reasons %v carry no foreign-builder marker", r.Reasons)
}

func TestVerifierDemandsBothPredicateTypes(t *testing.T) {
	localBuilder := "https://github.com/trishula-dev/trishula/.github/workflows/release-attest.yml@refs/heads/main"
	provenanceOnly := map[string][]Bundle{
		assetSHA: {bundleFor(t, provenanceStatement([]string{assetSHA}, localBuilder))},
	}
	results := verifierOf([]AssetSpec{{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA}}, provenanceOnly).Verify("2026.01-rc1")
	if len(results) != 1 {
		t.Fatalf("Verify() returned %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusReject {
		t.Errorf("status %q, want %q with the SBOM statement absent", r.Status, StatusReject)
	}
	if !r.Provenance {
		t.Errorf("provenance verdict %v, want true while its statement matches", r.Provenance)
	}
	if r.SBOM {
		t.Errorf("sbom verdict %v, want false — provenance alone does not carry the SBOM side", r.SBOM)
	}
}

func TestVerifierFailsClosedOnFetchError(t *testing.T) {
	probe := errors.New("attestation store probe: 503")
	results := (&Verifier{
		List:          stubLister{assets: []AssetSpec{{Name: "bpf_shield_x86_bpfel.o", SHA256: assetSHA}}},
		Fetch:         stubFetcher{err: probe},
		BuilderPrefix: "https://github.com/trishula-dev/trishula/",
	}).Verify("2026.01-rc1")
	if len(results) != 1 {
		t.Fatalf("Verify() returned %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusReject {
		t.Errorf("status %q, want %q — an unknown attestation state rejects, never passes", r.Status, StatusReject)
	}
	if len(r.Reasons) == 0 || !strings.Contains(r.Reasons[0], "503") {
		t.Errorf("reasons %v carry no probe failure marker", r.Reasons)
	}
}

func TestVerifierRejectsAssetWithoutDigest(t *testing.T) {
	results := verifierOf([]AssetSpec{{Name: "upload-in-flight.o"}}, map[string][]Bundle{}).Verify("2026.01-rc1")
	if len(results) != 1 {
		t.Fatalf("Verify() returned %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != StatusReject {
		t.Errorf("status %q, want %q for an asset with no digest on the release-assets surface", r.Status, StatusReject)
	}
	if len(r.Reasons) == 0 || !strings.Contains(r.Reasons[0], "no sha256 digest") {
		t.Errorf("reasons %v carry no missing-digest marker", r.Reasons)
	}
}

func TestVerifierFailsClosedOnListError(t *testing.T) {
	results := (&Verifier{
		List:          stubListerErr{err: errors.New("release-assets list: 503")},
		Fetch:         stubFetcher{},
		BuilderPrefix: "https://github.com/trishula-dev/trishula/",
	}).Verify("2026.01-rc1")
	if len(results) != 1 {
		t.Fatalf("Verify() returned %d results, want 1 (the list failure is its own reject verdict)", len(results))
	}
	if results[0].Status != StatusReject {
		t.Errorf("status %q, want %q — a failed release-assets read never passes", results[0].Status, StatusReject)
	}
	if len(results[0].Reasons) == 0 || !strings.Contains(results[0].Reasons[0], "503") {
		t.Errorf("reasons %v carry no list failure marker", results[0].Reasons)
	}
}
