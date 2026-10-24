// Package crd is the validation layer CUE adds on top of the controller-gen
// output (TR-46 census row "Committed CRD output", issue #192). The Go types
// in api/v1alpha1 stay the schema source: controller-gen owns the CRD bytes
// and its determinism test pins them byte-for-byte. This package mirrors the
// v1alpha1 WAFPolicy surface in CUE and every cue-gate run vets the
// committed CRD against it, so a regeneration that drifts the semantics is
// caught without a build. The lab CUE policies (cue/lab/dx1) validate against
// the same spec schema, which keeps the CRD, the lab manifests and the CUE
// layer on one definition.
package crd

import "list"

// DefaultAction is the default verdict when no rule set fires (api/v1alpha1
// DefaultAction).
#DefaultAction: "block" | "challenge" | "log" | "pass"

// CRSProfile is the CRS paranoia level (api/v1alpha1 CRSProfile).
#CRSProfile: "PL1" | "PL2" | "PL3"

// RouteAction is the kernel-path verdict of one route class
// (api/v1alpha1 RouteAction).
#RouteAction: "forward" | "drop"

// ModeFlags select the enforcement planes (api/v1alpha1 PolicyModeFlags;
// the flags are optional booleans like the omitempty Go fields).
#ModeFlags: {
	inline?: bool
	shield?: bool
	shadow?: bool
}

// RuleSetSource declares the rule set's upstream
// (api/v1alpha1 RuleSetSource).
#RuleSetSource: {
	crsVersion: string
	profile:    #CRSProfile
	...
}

// RuleSetRef binds one rule set into the policy (api/v1alpha1 RuleSetRef).
#RuleSetRef: {
	name:   string
	source: #RuleSetSource
	...
}

// RouteMark selects one HTTP path-prefix class and its kernel-path action
// (api/v1alpha1 RouteMark).
#RouteMark: {
	prefix: string
	action: #RouteAction
	...
}

// WAFPolicySpec is the desired policy state for a route class
// (api/v1alpha1 WAFPolicySpec). The two list bounds restate the CRD's
// maxItems; each guard runs only when the list is present, so an absent
// list stays a valid instance.
#WAFPolicySpec: {
	defaultAction: #DefaultAction
	modeFlags:     #ModeFlags
	ruleSets?: [...#RuleSetRef]
	routes?: [...#RouteMark]
	celBudget?: >=0
	if ruleSets != _|_ {
		_maxRuleSets: list.MaxItems(ruleSets, 16) & true
	}
	if routes != _|_ {
		_maxRoutes: list.MaxItems(routes, 8) & true
	}
}

// The enumerations the CRD's OpenAPI v3 schema carries for the policy
// fields. controller-gen emits each enum twice (two allOf entries); the
// schema below reasserts that exact shape.
#PolicyActionEnumeration: ["block", "challenge", "log", "pass"]
#PolicyProfileEnumeration: ["PL1", "PL2", "PL3"]
#PolicyRouteEnumeration: ["forward", "drop"]

// WAFPolicyCRDJsonSchema mirrors the semantic core of the CRD's
// openAPIV3Schema: the checks the API server applies on every apply stay
// visible here. Untouched node parts stay open with `...`.
#WAFPolicyCRDJsonSchema: {
	type: "object"
	required: ["spec"]
	properties: {
		apiVersion: {type: "string", ...}
		kind: {type: "string", ...}
		metadata: {type: "object", ...}
		spec: {
			type: "object"
			required: ["defaultAction", "modeFlags"]
			properties: {
				defaultAction: {
					type: "string"
					allOf: [{enum: #PolicyActionEnumeration}, {enum: #PolicyActionEnumeration}]
					...
				}
				modeFlags: {
					type: "object"
					properties: {
						inline: {type: "boolean", ...}
						shadow: {type: "boolean", ...}
						shield: {type: "boolean", ...}
					}
					...
				}
				celBudget: {
					type:    "integer"
					minimum: 0
					...
				}
				ruleSets: {
					type:     "array"
					maxItems: 16
					...
				}
				routes: {
					type:     "array"
					maxItems: 8
					...
				}
			}
			...
		}
		status: {type: "object", ...}
	}
	...
}

// WAFPolicyCRD is the envelope schema for the committed CRD file
// (manifests/crd/wafpolicy-crd.yaml).
#WAFPolicyCRD: {
	apiVersion: "apiextensions.k8s.io/v1"
	kind:       "CustomResourceDefinition"
	metadata: {
		name: "wafpolicies.trishula.security"
		...
	}
	spec: {
		group: "trishula.security"
		names: {
			kind:   "WAFPolicy"
			plural: "wafpolicies"
			...
		}
		scope: "Namespaced"
		versions: [...{
			name:    "v1alpha1"
			served:  true
			storage: true
			schema: {
				openAPIV3Schema: #WAFPolicyCRDJsonSchema
			}
			...
		}]
		...
	}
	...
}

// WAFPolicy is the CR object shape (api/v1alpha1.WAFPolicy): the object the
// lab manifests and future policy-surface CUE packages carry. The spec field
// is #WAFPolicySpec — the same schema the CRD's OpenAPI layer validates.
#WAFPolicy: {
	apiVersion: "trishula.security/v1alpha1"
	kind:       "WAFPolicy"
	metadata: {
		name:       string
		namespace?: string
		labels?: {[string]: string}
		...
	}
	spec: #WAFPolicySpec
	status?: {
		conditions?: [...{...}]
		...
	}
}
