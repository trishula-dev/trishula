package positive

// RED (TR-18): drift telemetry harness. The diff vocabulary is the
// contract; the Drift body is a stub pending the GREEN commit. The
// GREEN work pins the walk: reviewed-route coverage, field presence,
// type, enum, length and required-set divergence, and the unrepresentable
// records, read off the learned spec's cardinality.

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

// Drift reads the live-vs-reviewed divergence: the learned spec against
// the loaded (reviewed) policy (RED stub).
func Drift(live *LearnedSpec, reviewed *Policy) *DriftReport {
	return &DriftReport{Counts: map[DiffKind]int{}}
}
