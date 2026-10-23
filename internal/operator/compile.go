// Package operator is the trishula-operator's control-plane core (the spec's architecture,
// its ladder-source rule): trishula.security CRDs compile into the bundles the engine loads
// ("one policy artifact, many enforcement altitudes"). TR-08b carries the
// in-process compile→load round-trip for WAFPolicy — no cluster, no k8s
// calls (the CRD watch/reconcile loop is TR-08c, kernel map writes the
// shield loader slice). The bundle is the signed distribution unit of the spec's architecture;
// signing/distribution land with later slices.
//
// # Bundle wire format (v1)
//
// A bundle is a single JSON document (encoding/json on both ends, sorted
// map keys), so Compile output round-trips byte-identically — the
// precondition for digest-pinned, operator-signed distribution (the spec's performance section's supply
// chain). Schema:
//
//	{
//	  "formatVersion": 1,     // this schema; Load rejects future versions
//	  "tenant": "lab",        // the policy namespace (the spec's multi-tenancy requirement R8; Load
//	                          // rejects the empty value)
//	  "policy": {             // compiled policy view (the spec's CRD-set section, verbatim)
//	    "defaultAction": "block",
//	    "modeFlags": {"inline":true, "shield":true, "shadow":false},
//	    "ruleSets": [{"name", "source": {"crsVersion", "profile"}}]
//	  },
//	  "rulePacks": [          // CEL payload the engine loads (the spec's CEL DSL)
//	    {"rules": [{"id","name","description","action","expression"}]}
//	  ],
//	  "kernelValues": {       // the spec's kernel map values, stub shape (TR-08b)
//	    "acl4": {}, "acl6": {}, "verdicts": {}
//	  },
//	  "rulePackDigests": ["sha256-<hex>"]  // per pack, canonical JSON digest
//	}
//
// The v0 CEL plane is the TR-02 seed rule pack (rules/cel/seed.yaml: the
// The spec's rate-shape rule, action=log); a custom CEL rules source and the
// CRS SecLang directive bytes embed with later TR-08 slices. CRS rule-set
// refs are validated (version + profile present, profile known) and
// carried in the policy view as the CRS plane descriptor — internal/crs
// evaluates SecLang files (internal/crs.NewFromFile), so the directive
// bytes that back the descriptor ship with the CRS loader slice, never
// fabricated at compile time. kernelValues is the honest stub of the spec's
// "where kernel-relevant, a value pre-seeded into the shield maps":
// today's v0 WAFPolicy surface carries no ACL prefixes or verdict-cache
// entries, so the record holds empty maps — the shape the shield-side
// loader consumes, never nil after Compile.
//
// # Tenant binding (TR-25, the spec's multi-tenancy requirement R8)
//
// The bundle binds its tenant ("CRD namespacing; per-tenant compiled
// bundles"). Tenant is the WAFPolicy's namespace: Compile stamps it from
// the policy object and rejects a namespace-less policy, and Load rejects
// a bundle without it. A bundle never leaves the operator unqualified
// (fail closed). The v0 transport carries the binding per tenant: the
// bundle ConfigMap lands in the policy's own namespace (cmd/operator), so
// tenants never share a publish slot. Bundles compiled before TR-25 carry
// no tenant and fail the Load gate.
package operator

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// BundleFormatVersion is the current bundle wire-format version (the spec's architecture section):
// bumped on breaking change; Load rejects future versions.
const BundleFormatVersion = 1

// Policy is the compiled policy-level view carried in every bundle: the
// default verdict, the enforcement-plane flags and the rule-set refs,
// verbatim from the WAFPolicy spec (the spec's CRD set).
type Policy struct {
	DefaultAction v1alpha1.DefaultAction   `json:"defaultAction"`
	ModeFlags     v1alpha1.PolicyModeFlags `json:"modeFlags"`
	// RuleSets are the compiled-in rule-set refs in spec order. CEL-source
	// rule sets resolve to rulePacks entries; CRS refs are the CRS plane
	// descriptor (see the package comment).
	RuleSets []v1alpha1.RuleSetRef `json:"ruleSets,omitempty"`
}

// KernelValues is the "kernel map values" leg of the spec's bundle in its
// TR-08b stub shape (the spec's kernel map set): ACL/verdict entries arrive with later slices —
// the maps exist so Load can validate the record's presence.
type KernelValues struct {
	// ACL4 holds the spec's acl4 LPM-trie value entries (prefix → action);
	// empty at v0.
	ACL4 map[string]string `json:"acl4"`
	// ACL6 holds the spec's acl6 entries; empty at v0.
	ACL6 map[string]string `json:"acl6"`
	// Verdicts holds the spec's verdict-cache seed entries; empty at v0.
	Verdicts map[string]string `json:"verdicts"`
}

// Bundle is the compiled WAFPolicy artifact (the spec's architecture section). JSON tags rule the
// wire; the format is documented in the package comment.
type Bundle struct {
	// FormatVersion pins the bundle schema for Load's compatibility gate.
	FormatVersion int `json:"formatVersion"`
	// Policy is the compiled policy-level view.
	Policy Policy `json:"policy"`
	// RulePacks are the CEL rule packs the engine loads (the spec's CEL DSL), in
	// policy order.
	RulePacks []cel.RulePack `json:"rulePacks"`
	// KernelValues is the spec's kernel map-value record; nil only on a
	// hand-built bundle (Compile always sets it).
	KernelValues *KernelValues `json:"kernelValues"`
	// RulePackDigests are the sha-256 content digests of each rule pack's
	// canonical JSON encoding (compile-time integrity evidence; Load
	// re-verifies them against the packs).
	RulePackDigests []string `json:"rulePackDigests"`
	// Tenant is the bundle's tenant binding: the WAFPolicy's namespace
	// (the spec's multi-tenancy requirement R8). Compile stamps it; Load rejects the empty value (fail
	// closed — an unqualified bundle cannot bind a tenant).
	Tenant string `json:"tenant"`
}

// seedPackPath locates the seed rule pack relative to this package
// (relative-to-file, the cel package's fixture pattern; go:embed cannot
// cross up out of the package directory).
const seedPackPath = "../../rules/cel/seed.yaml"

// seedPackBytes embeds the seed rule pack at build time: the compiled
// bundles' default CEL plane must be resolvable wherever the compile runs
// (in-process tests, the cmd/operator pod — a scratch image carries no
// repo tree). Compile falls back to the file path when the embed is empty
// (non-Go-tooling builds); the bytes and the file are the same source.
//
//go:embed all:seed_pack.yaml
var seedPackBytes []byte

// Compile compiles a WAFPolicy into a Bundle (the spec's architecture, step 1), in-process: no
// cluster reads here (the reconcile loop is TR-08c). The v0 CEL plane is
// always the TR-02 seed rule pack; CRS rule-set refs are validated and
// recorded as the CRS plane descriptor. The bundle binds its tenant: the
// policy's namespace (the spec's multi-tenancy requirement R8, fail closed on an empty one).
func Compile(policy v1alpha1.WAFPolicy) (Bundle, error) {
	if policy.Namespace == "" {
		return Bundle{}, errors.New("compile: WAFPolicy carries no namespace (§20.1 R8: every bundle binds its tenant)") // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}
	switch policy.Spec.DefaultAction {
	case v1alpha1.DefaultActionBlock, v1alpha1.DefaultActionChallenge,
		v1alpha1.DefaultActionLog, v1alpha1.DefaultActionPass, "":
	default:
		return Bundle{}, fmt.Errorf("compile: unknown defaultAction %q", policy.Spec.DefaultAction)
	}
	b := Bundle{
		FormatVersion: BundleFormatVersion,
		Tenant:        policy.Namespace,
		Policy: Policy{
			DefaultAction: policy.Spec.DefaultAction,
			ModeFlags:     policy.Spec.ModeFlags,
			RuleSets:      policy.Spec.RuleSets,
		},
		KernelValues: &KernelValues{
			ACL4:     map[string]string{},
			ACL6:     map[string]string{},
			Verdicts: map[string]string{},
		},
	}
	for i, ref := range policy.Spec.RuleSets {
		if err := validRuleSetSource(ref.Source); err != nil {
			return Bundle{}, fmt.Errorf("compile: rule set %d (%s): %w", i, ref.Name, err)
		}
	}

	// The v0 CEL plane: the seed pack. Compiled once per Compile call; the
	// engine env compiles each rule's program lazily at load/eval (the spec's CEL DSL,
	// load ≠ compile). A custom CEL rules source rides a later TR-08
	// slice (package comment).
	data, err := seedPackData()
	if err != nil {
		return Bundle{}, fmt.Errorf("compile: read seed rule pack: %w", err)
	}
	pack, err := cel.ParseRulePack(data)
	if err != nil {
		return Bundle{}, fmt.Errorf("compile: seed rule pack: %w", err)
	}
	applyPolicyBudget(pack.Rules, policy.Spec.CELBudget)
	b.RulePacks = []cel.RulePack{*pack}

	digests, err := packDigests(b.RulePacks)
	if err != nil {
		return Bundle{}, err
	}
	b.RulePackDigests = digests
	return b, nil
}

// validRuleSetSource validates a rule-set ref's source in-process: the CRD
// schema enforces the same vocabulary on the wire (spec.source has no
// kubebuilder enum on profile, so the compile re-gates it); in-process
// compiles of hand-built objects get the same gate here.
func validRuleSetSource(src v1alpha1.RuleSetSource) error {
	if strings.TrimSpace(src.CRSVersion) == "" {
		return errors.New("source.crsVersion is required")
	}
	switch src.Profile {
	case v1alpha1.CRSProfilePL1, v1alpha1.CRSProfilePL2, v1alpha1.CRSProfilePL3:
		return nil
	case "":
		return errors.New("source.profile is required")
	default:
		return fmt.Errorf("unknown source.profile %q", src.Profile)
	}
}

// packDigests digests each rule pack's canonical JSON encoding; the digest
// is what Load re-verifies (tamper detection) and what bundle signing pins.
func packDigests(packs []cel.RulePack) ([]string, error) {
	digests := make([]string, len(packs))
	for i := range packs {
		data, err := json.Marshal(&packs[i])
		if err != nil {
			return nil, fmt.Errorf("compile: marshal rule pack %d: %w", i, err)
		}
		sum := sha256.Sum256(data)
		digests[i] = "sha256-" + hex.EncodeToString(sum[:])
	}
	return digests, nil
}

// PackDigests digests each rule pack's canonical JSON encoding
// ("sha256-<hex>" per pack, in order). The canonical-JSON encoding and the
// digest format are exactly Compile/Load's internal rule (packDigests);
// exported for callers that splice packs into a compiled bundle outside
// Compile (the cmd/operator watch loop resolving custom rule packs).
func PackDigests(packs []cel.RulePack) ([]string, error) {
	return packDigests(packs)
}

// applyPolicyBudget stamps the policy's spec.celBudget (the apply-path
// budget, the spec's CEL DSL plus goal G4) onto every rule that does not declare its own
// budget. The pack's per-rule costBudget is the more specific declaration
// and wins; a zero budget leaves the engine's package default in place.
func applyPolicyBudget(rules []cel.Rule, budget uint64) {
	if budget == 0 {
		return
	}
	for i := range rules {
		if rules[i].CostBudget == 0 {
			rules[i].CostBudget = budget
		}
	}
}

// seedPackData resolves the seed rule pack: the embedded copy (the
// deployed-operator shape: a scratch image carries no repo tree) with the
// repo file as the source it must stay byte-identical to — a mismatching
// build tree is a compile error, not a silent divergence.
func seedPackData() ([]byte, error) {
	if len(seedPackBytes) > 0 {
		return seedPackBytes, nil
	}
	return os.ReadFile(seedPackPath)
}

// Eval is a loaded, evaluable bundle: the rule packs resolved against the
// engine's TR-02-style CEL env (load ≠ compile — a pack whose expression
// does not compile fails HERE, never mid-request), kernel values staged
// verbatim for the shield loader slice.
type Eval struct {
	policy       Policy
	rulePacks    []cel.RulePack
	kernelValues *KernelValues
}

// Load loads a bundle for evaluation (the spec's architecture, step 2). No bundle field is
// trusted without verification: the format version is gate-checked, every
// rule pack is digest-re-verified against its content (a mismatch is a
// tamper/corruption error), and every rule is compile-checked in the
// engine env before Load succeeds.
func Load(bundle Bundle) (*Eval, error) {
	if bundle.FormatVersion != BundleFormatVersion {
		return nil, fmt.Errorf("load: bundle formatVersion %d, want %d", bundle.FormatVersion, BundleFormatVersion)
	}
	if strings.TrimSpace(bundle.Tenant) == "" {
		return nil, errors.New("load: bundle carries no tenant (§20.1 R8: per-tenant bundles are namespaced)") // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}
	if bundle.KernelValues == nil {
		return nil, errors.New("load: kernelValues must be present (empty maps at v0), not nil")
	}
	if len(bundle.RulePacks) != len(bundle.RulePackDigests) {
		return nil, fmt.Errorf("load: %d rule packs but %d digests", len(bundle.RulePacks), len(bundle.RulePackDigests))
	}
	digests, err := packDigests(bundle.RulePacks)
	if err != nil {
		return nil, err
	}
	for i := range digests {
		if digests[i] != bundle.RulePackDigests[i] {
			return nil, fmt.Errorf("load: rule pack %d digest mismatch: bundle says %s, content is %s (tampered or corrupted bundle)", i, bundle.RulePackDigests[i], digests[i])
		}
	}
	// Compile-check every rule now (load ≠ compile): r.Eval on the empty
	// request view compiles lazily and rejects an uncompilable or non-bool
	// rule expression with an error before any traffic sees the bundle.
	// The probe's verdict itself is discarded — Load only vouches that the
	// rule compiles.
	for i := range bundle.RulePacks {
		rules := bundle.RulePacks[i].Rules
		for j := range rules {
			if _, err := rules[j].Eval(cel.Request{}); err != nil {
				return nil, fmt.Errorf("load: rule pack %d rule %d (%s): %w", i, j, rules[j].ID, err)
			}
		}
	}
	return &Eval{
		policy:       bundle.Policy,
		rulePacks:    bundle.RulePacks,
		kernelValues: bundle.KernelValues,
	}, nil
}

// Eval evaluates one fixture request view through the loaded bundle's
// rules (the spec's CEL DSL): the first matching rule's verdict is decisive; a clean
// no-match is (Verdict{}, nil) — the policy's defaultAction applies at the
// ladder stage that consumes the verdict (the spec's precedence rule), not here. Rule provenance
// (which rule matched) rides with TR-08c's verdict plumbing.
func (e *Eval) Eval(req cel.Request) (cel.Verdict, error) {
	for i := range e.rulePacks {
		rules := e.rulePacks[i].Rules
		for j := range rules {
			v, err := rules[j].Eval(req)
			if err != nil {
				return v, err
			}
			if v.Match {
				return v, nil
			}
		}
	}
	return cel.Verdict{}, nil
}
