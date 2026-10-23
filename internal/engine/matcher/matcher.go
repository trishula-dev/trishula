// Package matcher implements PRD §11.4, the compiled fast path: the hot
// subset of CRS + CEL patterns compiles to one block-mode scan database
// (TR-16). One scan covers the pattern set over the §11.3 request view
// segments (uri, headers, query, body).
//
// R2b pressure valve (PRD §20.1): subset selection by frequency carries the
// memory budget — patterns that fall outside the budget stay reference-path
// only (never compiled). The differential gate (PRD §11.4/§11.8) compares
// matcher verdicts against the reference evaluator per pattern; a pattern
// that diverges is demoted to reference-path-only (self-healing parity).
//
// Slice boundary (TR-16): the selection, compile, scan and demotion seam in
// pure Go (stdlib RE2: no catastrophic backtracking, PRD §18.2). The native
// Vectorscan compile behind this seam and the S1 ladder wiring are later
// slices; the reference verdicts arrive injected (no evaluator dependency).
package matcher

import (
	"errors"
	"regexp"
)

// Path is where a pattern evaluates: in the compiled hot database, or on
// the reference path only.
type Path string

const (
	// PathActive compiles the pattern into the hot-subset database.
	PathActive Path = "active"
	// PathReference keeps the pattern on the reference evaluator path
	// only (budget demotion or differential divergence).
	PathReference Path = "reference"
)

// Phase values mirror the reference evaluator phases (internal/crs).
const (
	PhaseRequestHeaders = 1
	PhaseRequestBody    = 2
)

// Pattern is one rule in the compiled set: the reference rule id it
// mirrors, the view segments it scans, and its RE2 expression.
type Pattern struct {
	// Rule is the reference rule id the pattern mirrors (e.g. 942480).
	Rule int
	// Phase is the reference phase the pattern contributes in
	// (PhaseRequestHeaders or PhaseRequestBody).
	Phase int
	// Surfaces name the view segments the pattern scans (e.g. "query",
	// "body", "headers", "uri"). An unknown surface at scan time never
	// fires the pattern.
	Surfaces []string
	// Expr is the RE2 expression compiled into the database.
	Expr string
	// Path records where the pattern evaluates (default PathActive).
	Path Path
}

// Set is the pattern set under hot-subset management: every pattern
// carries a Path (active or reference-only).
type Set struct {
	patterns []Pattern
}

// DB is the compiled block-mode scan database (the hot subset).
type DB struct {
	rules    []int
	res      map[int]*regexp.Regexp
	surfaces map[int][]string
	phases   map[int]int
}

// NewSet builds a Set; a duplicate rule id or an empty expression fails
// the build (a malformed pattern is a load error, never a silent skip).
func NewSet(patterns []Pattern) (*Set, error) {
	return nil, errors.New("matcher: not implemented")
}

// SelectHot applies the R2b subset selection: ranking by frequency,
// descending; ties break by rule id, ascending. The top budget patterns
// stay on the hot path; the rest move to PathReference. A nil freq or a
// non-positive budget is a configuration error.
func (s *Set) SelectHot(freq func(rule int) uint64, budget int) (active []Pattern, referenceOnly []Pattern, err error) {
	return nil, nil, errors.New("matcher: not implemented")
}

// Active returns the patterns currently on the hot path.
func (s *Set) Active() []Pattern {
	return nil
}

// ReferenceOnly returns the patterns currently demoted off the hot path.
func (s *Set) ReferenceOnly() []Pattern {
	return nil
}

// Demote moves the named rules to PathReference (the self-healing parity
// action, PRD §11.8). An unknown rule id is an error: demotion never
// removes a phantom. Re-demoting a reference-only rule is a no-op.
func (s *Set) Demote(rules ...int) error {
	return errors.New("matcher: not implemented")
}

// Compile compiles the active pattern list into the block-mode DB. A bad
// expression fails here (load-time discipline: a broken pattern fails the
// load, never a mid-request scan). Reference-path patterns in the input
// are a configuration error.
func Compile(active []Pattern) (*DB, error) {
	return nil, errors.New("matcher: not implemented")
}

// Scan runs one pass over the view segments for the given phase and
// returns the matched rule ids in ascending order, deduplicated. Patterns
// of another phase, or with no surface present in the view, do not fire.
func (db *DB) Scan(phase int, view map[string]string) []int {
	return nil
}
