package positive

import (
	"fmt"
	"sort"
	"strings"
)

// GREEN (TR-18): the drift read (§11.5): the learned spec against the
// loaded (reviewed) policy, read off the cardinality census. Every row
// names the endpoint, the schema position and the measured evidence; the
// per-kind counts are the schema-drift counters' record source (the otel
// wiring stays the otel slice). Patterns are never compared — inference
// does not produce them (learn.go).

// DiffKind names one class of live-vs-reviewed divergence (§11.5 drift
// telemetry). The kinds are the drift vocabulary — extend, never fork.
type DiffKind string

// The drift vocabulary (§11.5).
const (
	DiffEndpointAdded      DiffKind = "endpoint_added"      // live route absent from the reviewed policy
	DiffEndpointUnobserved DiffKind = "endpoint_unobserved" // reviewed route with no live samples
	DiffFieldAdded         DiffKind = "field_added"         // observed field the reviewed schema does not describe
	DiffFieldMissing       DiffKind = "field_missing"       // reviewed field never observed in the window
	DiffTypeDrift          DiffKind = "type_drift"          // observed value kind contradicts the reviewed type
	DiffEnumEscape         DiffKind = "enum_escape"         // observed value outside the reviewed enum
	DiffLengthOverflow     DiffKind = "length_overflow"     // observed length exceeds the reviewed maxLength
	DiffRequiredDrift      DiffKind = "required_drift"      // required sets disagree in the window
	DiffUnrepresentable    DiffKind = "unrepresentable"     // observed shape the v0 subset cannot describe
)

// Diff is one live-vs-reviewed divergence row — the CR-diff record the
// operator reads before editing the policy document (learn mode emits
// diffs for review; the application into the APISpec CR stays a named
// follow-up until the CRD lands).
type Diff struct {
	Kind  DiffKind
	Route string // endpoint path (always set)
	Path  string // schema-position path ("body.model"); "" on route-level rows
	Note  string // one-line detail carrying the measured evidence
}

// DriftReport is the drift telemetry read (§11.5): the live-vs-reviewed
// divergence as data — the record set plus the per-kind counts the
// schema-drift counters derive from (the otel wiring is the otel slice,
// not this package).
type DriftReport struct {
	Diffs          []Diff
	Counts         map[DiffKind]int
	LiveEndpoints  int
	ReviewedRoutes int
	LiveSamples    int
}

// HasDrift reports whether the report carries any divergence row.
func (r *DriftReport) HasDrift() bool {
	if r == nil {
		return false
	}
	return len(r.Diffs) > 0
}

// Drift reads the live-vs-reviewed divergence rows: reviewed-schema
// positions walked against the live census, endpoint-set comparison both
// ways, and one row per unrepresentable record. A nil live side reads as
// an empty window; a nil reviewed side reads as no reviewed policy.
func Drift(live *LearnedSpec, reviewed *Policy) *DriftReport {
	rep := &DriftReport{Counts: map[DiffKind]int{}}
	if reviewed != nil {
		rep.ReviewedRoutes = len(reviewed.routes)
	}
	if live != nil {
		rep.LiveEndpoints = len(live.Routes)
		rep.LiveSamples = live.Samples
	}
	add := func(d Diff) {
		rep.Diffs = append(rep.Diffs, d)
		rep.Counts[d.Kind]++
	}

	// Reviewed side: every reviewed endpoint either carries live
	// observations (the schema walk against the census) or none (the
	// endpoint-unobserved row).
	if reviewed != nil {
		for _, path := range sortedPolicyRoutes(reviewed) {
			if live == nil || live.Routes[path] == nil {
				add(Diff{Kind: DiffEndpointUnobserved, Route: path,
					Note: "endpoint in the reviewed policy with no live samples in the window"})
				continue
			}
			lr := live.Routes[path]
			cards := cardIndex(lr)
			driftWalk(reviewed.routes[path].schema, "body", lr, cards, add)
		}
	}

	// Live side: endpoints the reviewed policy does not describe, plus
	// every unrepresentable record (the window can carry more than the
	// v0 schema subset can express — the overflow is a review item
	// either way).
	if live != nil {
		for _, path := range sortedLiveRoutes(live) {
			lr := live.Routes[path]
			if reviewed == nil {
				add(Diff{Kind: DiffEndpointAdded, Route: path,
					Note: "endpoint observed in live traffic, absent from the reviewed policy"})
			} else if _, inReviewed := reviewed.routes[path]; !inReviewed {
				add(Diff{Kind: DiffEndpointAdded, Route: path,
					Note: "endpoint observed in live traffic, absent from the reviewed policy"})
			}
			for _, p := range lr.Unrepresentable {
				add(Diff{Kind: DiffUnrepresentable, Route: path, Path: p, Note: unrepNote(lr, p)})
			}
		}
	}

	sort.Slice(rep.Diffs, func(i, j int) bool {
		a, b := rep.Diffs[i], rep.Diffs[j]
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Note < b.Note
	})
	return rep
}

// cardIndex indexes one route's cardinality read by path.
func cardIndex(lr *LearnedRoute) map[string]FieldCardinality {
	m := make(map[string]FieldCardinality, len(lr.Cardinality))
	for _, c := range lr.Cardinality {
		m[c.Path] = c
	}
	return m
}

// sortedPolicyRoutes names the reviewed policy's routes in order.
func sortedPolicyRoutes(p *Policy) []string {
	out := make([]string, 0, len(p.routes))
	for path := range p.routes {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// sortedLiveRoutes names the learned spec's routes in order.
func sortedLiveRoutes(s *LearnedSpec) []string {
	out := make([]string, 0, len(s.Routes))
	for path := range s.Routes {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// driftWalk walks one reviewed schema position against the live census
// and appends the divergence rows under it (Drift sorts once at the end).
func driftWalk(rev *Schema, path string, lr *LearnedRoute, cards map[string]FieldCardinality, add func(Diff)) {
	if rev == nil {
		return
	}
	// The type read: every observed kind that contradicts the reviewed
	// type (mixed kinds also refuse the inference — both rows carry
	// their own evidence).
	if card, ok := cards[path]; ok && card.Present > 0 {
		for _, k := range card.Kinds {
			if k != rev.typ {
				add(Diff{Kind: DiffTypeDrift, Route: lr.Path, Path: path,
					Note: fmt.Sprintf("value kind %q contradicts the reviewed type %q", k, rev.typ)})
			}
		}
	}
	switch rev.typ {
	case "object":
		for _, name := range sortedSchemaFields(rev) {
			child := rev.properties[name]
			childPath := path + "." + name
			childCard, seen := cards[childPath]
			if !seen || childCard.Present == 0 {
				add(Diff{Kind: DiffFieldMissing, Route: lr.Path, Path: childPath,
					Note: fmt.Sprintf("reviewed field has no live observations in the window (%d values at this schema position)", cards[path].Present)})
				continue
			}
			// The required read: the presence ratio in the window
			// against the reviewed requirement, in both directions.
			liveRequired := childCard.Present == childCard.Seen
			revRequired := containsRevRequired(rev, name)
			if liveRequired != revRequired {
				add(Diff{Kind: DiffRequiredDrift, Route: lr.Path, Path: childPath,
					Note: requiredNote(childCard, liveRequired, revRequired)})
			}
			cardChecks(child, childCard, lr.Path, childPath, add)
			driftWalk(child, childPath, lr, cards, add)
		}
		for _, f := range cardFields(cards, path) {
			if _, known := rev.properties[f]; !known {
				add(Diff{Kind: DiffFieldAdded, Route: lr.Path, Path: path + "." + f,
					Note: "field observed in live traffic, absent from the reviewed schema"})
			}
		}
	case "array":
		if rev.items == nil {
			return // the v0 subset requires array items; strict loads refuse the rest
		}
		elPath := path + "[]"
		elCard, seen := cards[elPath]
		if !seen || elCard.Present == 0 {
			add(Diff{Kind: DiffFieldMissing, Route: lr.Path, Path: elPath,
				Note: "array element shape has no live observations in the window"})
			return
		}
		cardChecks(rev.items, elCard, lr.Path, elPath, add)
		driftWalk(rev.items, elPath, lr, cards, add)
	}
}

// cardChecks reads the string-census rows against a reviewed string
// schema: the enum escapes (one row per escaped value; a census above
// the cap carries no value list and reads none) and the length overflow.
func cardChecks(rev *Schema, card FieldCardinality, route, path string, add func(Diff)) {
	if rev == nil {
		return
	}
	if rev.typ == "string" && len(rev.enum) > 0 && card.Present > 0 && !card.OverCap {
		for _, v := range card.Values {
			if !containsRevEnum(rev, v) {
				add(Diff{Kind: DiffEnumEscape, Route: route, Path: path,
					Note: fmt.Sprintf("value %q is outside the reviewed enum %s", v, splitEnum(rev.enum))})
			}
		}
	}
	if rev.typ == "string" && rev.maxLength != nil && card.MaxLength > *rev.maxLength {
		add(Diff{Kind: DiffLengthOverflow, Route: route, Path: path,
			Note: fmt.Sprintf("observed maxLength %d exceeds the reviewed maxLength %d", card.MaxLength, *rev.maxLength)})
	}
}

// sortedSchemaFields names the reviewed schema's property fields sorted.
func sortedSchemaFields(rev *Schema) []string {
	out := make([]string, 0, len(rev.properties))
	for name := range rev.properties {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// containsRevRequired reports whether the reviewed schema requires name.
func containsRevRequired(rev *Schema, name string) bool {
	for _, r := range rev.required {
		if r == name {
			return true
		}
	}
	return false
}

// containsRevEnum reports whether the reviewed enum carries the value.
func containsRevEnum(rev *Schema, value string) bool { return stringIn(rev.enum, value) }

// stringIn reports whether list carries s.
func stringIn(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// cardFields names the live census's direct child fields at a site (the
// element sites and deeper positions stay out).
func cardFields(cards map[string]FieldCardinality, sitePath string) []string {
	prefix := sitePath + "."
	var out []string
	for p := range cards {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p[len(prefix):]
		if strings.Contains(rest, ".") || strings.HasSuffix(rest, "[]") {
			continue
		}
		out = append(out, rest)
	}
	sort.Strings(out)
	return out
}

// requiredNote words the required-drift evidence (the census counts, in
// the direction the row carries).
func requiredNote(card FieldCardinality, liveRequired, revRequired bool) string {
	ratio := fmt.Sprintf("present %d of %d", card.Present, card.Seen)
	switch {
	case liveRequired && !revRequired:
		return "required in the live window (" + ratio + "), optional in the reviewed schema"
	default:
		return "required in the reviewed schema, optional in the live window (" + ratio + ")"
	}
}

// unrepNote words one unrepresentable record from the observed kinds.
func unrepNote(lr *LearnedRoute, path string) string {
	card, ok := cardIndex(lr)[path]
	if !ok {
		return "observed shape outside the v0 schema subset"
	}
	switch {
	case len(card.Kinds) == 1 && card.Kinds[0] == "array":
		return "array element shape never observed (or mixed outside the v0 subset)"
	case len(card.Kinds) == 1 && card.Kinds[0] == "object":
		return "every observed field of the object sits outside the v0 subset"
	default:
		return fmt.Sprintf("observed kinds %s are outside the v0 schema subset", splitEnum(card.Kinds))
	}
}
