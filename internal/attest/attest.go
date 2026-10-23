// Package attest decides the release-asset attestation contract (TR-81,
// issue #120): every asset a release publishes carries a build-provenance
// attestation (predicate type https://slsa.dev/provenance/v1) and an SBOM
// attestation (predicate type https://spdx.dev/Document/v2.3), each with the
// statement subject digest bound to the asset digest. The lister and the
// attestation fetcher are injected surfaces, so the host CI suite runs
// without network access; the shipped adapters read the GitHub
// release-assets surface and the repository attestation store.
//
// The verifier is a structural gate. It checks statement presence, subject
// digest binding, required predicate types and the builder identity prefix.
// It does not verify signatures; `gh attestation verify` holds the
// cryptographic step (Sigstore certificate + Rekor transparency log).
// PRD ref: https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#181-assets-and-trust-boundaries
package attest

// PredProvenance is the required SLSA v1.0 build-provenance predicate type.
const PredProvenance = "https://slsa.dev/provenance/v1"

// PredSBOM is the required SPDX SBOM predicate type.
const PredSBOM = "https://spdx.dev/Document/v2.3"

// Status names the verdict the verifier reports for one release asset.
type Status string

// StatusPass and StatusReject are the only statuses the verifier reports.
const (
	StatusPass   Status = "pass"
	StatusReject Status = "reject"
)

// AssetSpec names one release asset and its digest. SHA256 carries the
// digest in the release-assets surface form, "sha256:<hex>".
type AssetSpec struct {
	Name   string
	SHA256 string
}

// Statement carries one decoded in-toto statement from an attestation
// bundle. SubjectSHA256 is in the "sha256:<hex>" form. Builder is the
// provenance predicate's builder.id; SBOM statements carry it empty.
type Statement struct {
	PredicateType string
	SubjectSHA256 string
	Builder       string
}

// Bundle carries one Sigstore bundle object as the attestations REST
// surface returns it (a JSON object, not a base64 blob).
type Bundle []byte

// Lister reads the release-assets surface.
type Lister interface {
	Assets(tag string) ([]AssetSpec, error)
}

// Fetcher reads the attestation store for one asset digest. An unknown
// digest returns a nil bundle slice with no error: absence is a verdict,
// not a fetch failure.
type Fetcher interface {
	Bundles(digest string) ([]Bundle, error)
}

// Verifier decides the attestations contract for one release. List and
// Fetch are injected. BuilderPrefix is the accepted provenance builder
// identity prefix; empty means no builder check.
type Verifier struct {
	List          Lister
	Fetch         Fetcher
	BuilderPrefix string
}

// AssetResult is the verdict for one release asset plus its reasons.
type AssetResult struct {
	Asset      AssetSpec
	Status     Status
	Provenance bool
	SBOM       bool
	Reasons    []string
}

// Verify decides every asset of the named release in order.
//
// TR-81 RED stub: the GREEN commit fills the decision logic. The nil
// return makes every contract test fail on camera until then.
func (v *Verifier) Verify(tag string) []*AssetResult {
	return nil
}
