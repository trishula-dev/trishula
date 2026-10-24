package fastpath

// This file carries the compile-split record (the census record's section
// 6): one per-field verdict pair per classified field a policy carries,
// plus the summary-reason vocabulary. It stays classification-only. No
// function here loads a kernel object or claims enforcement.
//
// Two surfaces carry the split. The per-field annotation holds the Fields
// map as JSON. The summary condition holds one Reason. The compile stamps
// kernel-free provable reasons only; the compile-to-load round-trip stamps
// the verifier-proved reasons.

import (
	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
)

// Reason is the summary-condition reason vocabulary (the census record's
// split section; Gateway API condition style). The round-trip owns the
// load-proved reasons; the compile owns the classification-provable ones.
type Reason string

// The summary-condition reasons.
const (
	// ReasonNoKernelFields: no classified field carries a kernel verdict;
	// the compile proves it from classification alone.
	ReasonNoKernelFields Reason = "NoKernelFields"
	// ReasonGateLocked: kernel-eligible fields sit present, every gate is
	// locked. No kernel artifact compiles.
	ReasonGateLocked Reason = "GateLocked"
	// ReasonEnvelopeExceeded: a bundle passes the program envelope. The
	// round-trip or a later compile gate stamps it.
	ReasonEnvelopeExceeded Reason = "EnvelopeExceeded"
	// ReasonVerifierRejected: the verifier refused a program. The
	// round-trip stamps it after a live load.
	ReasonVerifierRejected Reason = "VerifierRejected"
	// ReasonCompiled: the verifier accepted the instantiated program. The
	// round-trip stamps it after a live load.
	ReasonCompiled Reason = "Compiled"
)

// String returns the reason name.
func (r Reason) String() string { return string(r) }

// Split is one policy's compile-split record: one per-field verdict pair
// per classified field the policy carries. The compile writes the Fields
// map into the bundle; the round-trip stamps it as the policy annotation.
type Split struct {
	// Fields maps one census field path to its verdict. Present fields
	// only: a field the policy never carries carries no pair.
	Fields map[string]Verdict
}

// PolicySplit classifies the census-carrying fields the policy sets, in
// the record's split vocabulary. Presence rules: a slice counts present
// when it is non-empty, a string when it is non-empty, a flag when true,
// the CEL budget when greater than 0. An absent field carries no pair —
// the record claims nothing for a field the policy never set.
//
// Every pair reads through Classify, so the census map stays the single
// home of the field classes. The route rows carry their class verdict; the
// other present rows stay slow-path at the tracked surface.
func PolicySplit(policy v1alpha1.WAFPolicy) Split {
	fields := map[string]Verdict{}
	add := func(field string, present bool) {
		if !present {
			return
		}
		class, err := Classify(field)
		if err != nil {
			// The paths above are census rows; a drift fails the coverage
			// suite and never reaches callers as a silent skip.
			return
		}
		fields[field] = class.Verdict()
	}
	ruleSets := policy.Spec.RuleSets
	add("spec.ruleSets[].name", len(ruleSets) > 0)
	add("spec.ruleSets[].source.crsVersion", len(ruleSets) > 0)
	add("spec.ruleSets[].source.profile", len(ruleSets) > 0)
	add("spec.defaultAction", policy.Spec.DefaultAction != "")
	add("spec.celBudget", policy.Spec.CELBudget > 0)
	add("spec.modeFlags.inline", policy.Spec.ModeFlags.Inline)
	add("spec.modeFlags.shield", policy.Spec.ModeFlags.Shield)
	add("spec.modeFlags.shadow", policy.Spec.ModeFlags.Shadow)
	add("spec.routes[].prefix", len(policy.Spec.Routes) > 0)
	add("spec.routes[].action", len(policy.Spec.Routes) > 0)
	add("metadata.name", policy.Name != "")
	add("metadata.namespace", policy.Namespace != "")
	return Split{Fields: fields}
}
