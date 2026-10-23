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

import (
	"fmt"
	"strings"
)

// PredProvenance is the required SLSA v1.0 build-provenance predicate type.
const PredProvenance = "https://slsa.dev/provenance/v1"

// PredSBOM is the required SPDX SBOM predicate type.
const PredSBOM = "https://spdx.dev/Document/v2.3"

// Reject reasons the verifier reports. The contract tests pin these forms.
const (
	reasonMissingPredicate = "missing attestation predicate"
	reasonSubjectMismatch  = "statement subject digest does not match the asset digest"
	reasonForeignBuilder   = "provenance builder is outside the repository identity"
	reasonFetchFailed      = "attestation fetch failed"
	reasonListFailed       = "release-assets list failed"
	reasonNoAssetDigest    = "asset carries no sha256 digest on the release-assets surface"
	reasonBadBundle        = "attestation bundle decode failed"
)

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
// bundle. SubjectDigests holds every subject digest, in the
// "sha256:<hex>" form; the released statements name every release asset.
// Builder is the provenance predicate's builder.id; SBOM statements carry
// it empty.
type Statement struct {
	PredicateType  string
	SubjectDigests []string
	Builder        string
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

// Verify decides every asset of the named release in order. A failed
// release-assets read rejects as its own verdict: an unknown surface state
// never passes.
func (v *Verifier) Verify(tag string) []*AssetResult {
	assets, err := v.List.Assets(tag)
	if err != nil {
		return []*AssetResult{{
			Asset:   AssetSpec{Name: tag},
			Status:  StatusReject,
			Reasons: []string{fmt.Sprintf("%s: %v", reasonListFailed, err)},
		}}
	}
	results := make([]*AssetResult, 0, len(assets))
	for _, a := range assets {
		results = append(results, v.verifyAsset(a))
	}
	return results
}

func (v *Verifier) verifyAsset(a AssetSpec) *AssetResult {
	r := &AssetResult{Asset: a, Status: StatusReject}
	if a.SHA256 == "" {
		r.Reasons = []string{reasonNoAssetDigest}
		return r
	}
	bundles, err := v.Fetch.Bundles(a.SHA256)
	if err != nil {
		r.Reasons = []string{fmt.Sprintf("%s: %v", reasonFetchFailed, err)}
		return r
	}
	var provenance, sbom []Statement
	for _, b := range bundles {
		st, err := DecodeStatement(b)
		if err != nil {
			r.Reasons = append(r.Reasons, fmt.Sprintf("%s: %v", reasonBadBundle, err))
			continue
		}
		switch st.PredicateType {
		case PredProvenance:
			provenance = append(provenance, st)
		case PredSBOM:
			sbom = append(sbom, st)
		}
	}
	r.Provenance = v.bindStatement(provenance, a, true, &r.Reasons)
	r.SBOM = v.bindStatement(sbom, a, false, &r.Reasons)
	if r.Provenance && r.SBOM {
		r.Status = StatusPass
		r.Reasons = nil
	}
	return r
}

// bindStatement reports whether one candidate statement of the required
// predicate type binds the asset: any subject digest of the statement
// equals the asset digest and, for provenance, the builder id sits inside
// the repository identity. It appends the reject reasons where no
// statement binds.
func (v *Verifier) bindStatement(candidates []Statement, a AssetSpec, checkBuilder bool, reasons *[]string) bool {
	predicate := PredSBOM
	if checkBuilder {
		predicate = PredProvenance
	}
	if len(candidates) == 0 {
		*reasons = append(*reasons, fmt.Sprintf("%s: %s", reasonMissingPredicate, predicate))
		return false
	}
	for _, st := range candidates {
		bound := false
		for _, d := range st.SubjectDigests {
			if d == a.SHA256 {
				bound = true
				break
			}
		}
		if !bound {
			*reasons = append(*reasons, fmt.Sprintf("%s: %s", reasonSubjectMismatch, strings.Join(st.SubjectDigests, ", ")))
			continue
		}
		if checkBuilder && v.BuilderPrefix != "" && !strings.HasPrefix(st.Builder, v.BuilderPrefix) {
			*reasons = append(*reasons, fmt.Sprintf("%s: %s", reasonForeignBuilder, st.Builder))
			continue
		}
		return true
	}
	return false
}
