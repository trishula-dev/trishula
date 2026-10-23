// Package matcher implements the spec's Vectorscan section, the compiled fast path: the hot
// subset of CRS + CEL patterns compiles to one block-mode scan database
// (TR-16). One scan covers the pattern set over the spec's request view
// segments (uri, headers, query, body).
//
// R2b pressure valve (the spec's matcher-memory risk row R2b): subset selection by frequency carries the
// memory budget — patterns that fall outside the budget stay reference-path
// only (never compiled). The differential gate (the spec's Vectorscan and differential-parity sections) compares
// matcher verdicts against the reference evaluator per pattern; a pattern
// that diverges is demoted to reference-path-only (self-healing parity).
//
// Slice boundary (TR-16): the selection, compile, scan and demotion seam in
// pure Go (stdlib RE2: no catastrophic backtracking, the spec's threat model). The native
// Vectorscan compile behind this seam and the S1 ladder wiring are later
// slices; the reference verdicts arrive injected (no evaluator dependency).
package matcher

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
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

// DB is the compiled block-mode scan database (the hot subset): one pass
// per declared surface covers the whole pattern set (the Vectorscan seam;
// the RE2 engine keeps the scan backtracking-free, the spec's threat model).
type DB struct {
	byPhase map[int][]int
	res     map[int]*regexp.Regexp
	surface func(rule int) []string
}

// NewSet builds a Set; a duplicate rule id, an empty expression, or an
// unknown Path fails the build (a malformed pattern is a load error,
// never a silent skip).
func NewSet(patterns []Pattern) (*Set, error) {
	seen := map[int]int{}
	out := make([]Pattern, len(patterns))
	copy(out, patterns)
	for i := range out {
		p := out[i]
		if p.Rule <= 0 {
			return nil, fmt.Errorf("matcher: pattern rule id %d invalid", p.Rule)
		}
		if p.Expr == "" {
			return nil, fmt.Errorf("matcher: rule %d: empty expression", p.Rule)
		}
		if _, dup := seen[p.Rule]; dup {
			return nil, fmt.Errorf("matcher: duplicate rule id %d in pattern set", p.Rule)
		}
		seen[p.Rule] = i
		if p.Path == "" {
			out[i].Path = PathActive
		}
		if out[i].Path != PathActive && out[i].Path != PathReference {
			return nil, fmt.Errorf("matcher: rule %d: unknown path %q", p.Rule, p.Path)
		}
	}
	return &Set{patterns: out}, nil
}

// SelectHot applies the R2b subset selection: ranking by frequency,
// descending; ties break by rule id, ascending. The top budget patterns
// stay on the hot path; the rest move to PathReference. A nil freq or a
// non-positive budget is a configuration error.
func (s *Set) SelectHot(freq func(rule int) uint64, budget int) (active []Pattern, referenceOnly []Pattern, err error) {
	if freq == nil {
		return nil, nil, errors.New("matcher: nil frequency source")
	}
	if budget <= 0 {
		return nil, nil, fmt.Errorf("matcher: non-positive hot-subset budget %d", budget)
	}
	ranked := make([]Pattern, len(s.patterns))
	copy(ranked, s.patterns)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		fa, fb := freq(a.Rule), freq(b.Rule)
		if fa != fb {
			return fa > fb
		}
		return a.Rule < b.Rule
	})
	for i := range ranked {
		if i < budget {
			ranked[i].Path = PathActive
		} else {
			ranked[i].Path = PathReference
		}
	}
	s.patterns = ranked
	rankedBudget := budget
	if rankedBudget > len(ranked) {
		rankedBudget = len(ranked)
	}
	return activeOf(ranked), referenceOf(ranked), nil
}

// Active returns the patterns currently on the hot path.
func (s *Set) Active() []Pattern {
	return activeOf(s.patterns)
}

// ReferenceOnly returns the patterns currently demoted off the hot path.
func (s *Set) ReferenceOnly() []Pattern {
	return referenceOf(s.patterns)
}

// Demote moves the named rules to PathReference (the self-healing parity
// action, the spec's differential-parity gate). An unknown rule id is an error: demotion never
// removes a phantom. Re-demoting a reference-only rule is a no-op.
func (s *Set) Demote(rules ...int) error {
	for _, rule := range rules {
		idx := s.indexOf(rule)
		if idx < 0 {
			return fmt.Errorf("matcher: demote rule %d: not in set", rule)
		}
		s.patterns[idx].Path = PathReference
	}
	return nil
}

// indexOf returns the set position of the rule id, or -1.
func (s *Set) indexOf(rule int) int {
	for i := range s.patterns {
		if s.patterns[i].Rule == rule {
			return i
		}
	}
	return -1
}

// Compile compiles the active pattern list into the block-mode DB. A bad
// expression fails here (load-time discipline: a broken pattern fails the
// load, never a mid-request scan). Reference-path patterns in the input
// are a configuration error.
func Compile(active []Pattern) (*DB, error) {
	res := map[int]*regexp.Regexp{}
	surfaces := map[int][]string{}
	byPhase := map[int][]int{}
	for _, p := range active {
		if p.Path == PathReference {
			return nil, fmt.Errorf("matcher: compile input carries reference-path rule %d", p.Rule)
		}
		if p.Expr == "" {
			return nil, fmt.Errorf("matcher: rule %d: empty expression", p.Rule)
		}
		if _, seen := res[p.Rule]; seen {
			return nil, fmt.Errorf("matcher: duplicate rule id %d in compile input", p.Rule)
		}
		re, err := regexp.Compile(p.Expr)
		if err != nil {
			return nil, fmt.Errorf("matcher: rule %d: %w", p.Rule, err)
		}
		res[p.Rule] = re
		surfaces[p.Rule] = p.Surfaces
		byPhase[p.Phase] = append(byPhase[p.Phase], p.Rule)
	}
	return &DB{
		byPhase: byPhase,
		res:     res,
		surface: func(rule int) []string { return surfaces[rule] },
	}, nil
}

// Scan runs one pass over the view segments for the given phase and
// returns the matched rule ids in ascending order, deduplicated. Patterns
// of another phase, or with no surface present in the view, do not fire.
func (db *DB) Scan(phase int, view map[string]string) []int {
	var ids []int
	seen := map[int]bool{}
	for _, rule := range db.byPhase[phase] {
		for _, surf := range db.surface(rule) {
			payload, ok := view[surf]
			if !ok || payload == "" {
				continue
			}
			if db.res[rule].MatchString(payload) && !seen[rule] {
				seen[rule] = true
				ids = append(ids, rule)
				break
			}
		}
	}
	sort.Ints(ids)
	if ids == nil {
		ids = []int{}
	}
	return ids
}

// activeOf filters the hot-path patterns.
func activeOf(ps []Pattern) []Pattern {
	out := make([]Pattern, 0, len(ps))
	for _, p := range ps {
		if p.Path == PathActive {
			out = append(out, p)
		}
	}
	return out
}

// referenceOf filters the reference-path patterns.
func referenceOf(ps []Pattern) []Pattern {
	out := make([]Pattern, 0, len(ps))
	for _, p := range ps {
		if p.Path == PathReference {
			out = append(out, p)
		}
	}
	return out
}
