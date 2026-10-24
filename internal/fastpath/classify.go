package fastpath

import (
	"errors"
	"sort"
)

// ErrUnknownField reports a field outside the census. The classifier fails
// closed: an unlisted field never compiles, and a silent slow-path default
// would forge a record row.
var ErrUnknownField = errors.New("fastpath: field outside the census")

// fieldCensus maps one WAFPolicy field path to its compile class. The paths
// follow the CRD's JSON tree: the spec leaves of api/v1alpha1 (the TR-08a v0
// surface, the record's census section
// docs/design/socket-plane/4-compiler-census.md) plus the two metadata fields
// the compile stamps.
//
// Every v0 row routes to ClassSlowPath: the tracked surface carries no field
// of the kernel-offloadable subset, so the kernel path of the compiler
// compiles no field. The coverage test walks the CRD spec tree against this
// map and fails on a missing or stale row.
//
// The status subresource stays out of the map by design: the record's
// compile-split section owns status, not this skeleton's classifier.
var fieldCensus = map[string]Class{
	"spec.ruleSets[].name":              ClassSlowPath,
	"spec.ruleSets[].source.crsVersion": ClassSlowPath,
	"spec.ruleSets[].source.profile":    ClassSlowPath,
	"spec.defaultAction":                ClassSlowPath,
	"spec.celBudget":                    ClassSlowPath,
	"spec.modeFlags.inline":             ClassSlowPath,
	"spec.modeFlags.shield":             ClassSlowPath,
	"spec.modeFlags.shadow":             ClassSlowPath,
	"metadata.name":                     ClassSlowPath,
	"metadata.namespace":                ClassSlowPath,
}

// Classify returns the compile class of one WAFPolicy field. The field names
// in the census's path form ("spec.defaultAction", "metadata.namespace").
// Unknown fields fail closed with ErrUnknownField.
func Classify(field string) (Class, error) {
	class, ok := fieldCensus[field]
	if !ok {
		return "", ErrUnknownField
	}
	return class, nil
}

// Row is one census row: the field path and its compile class.
type Row struct {
	// Field is the census path ("spec.ruleSets[].name").
	Field string
	// Class is the compile class the record assigns the field.
	Class Class
}

// CensusRows returns the census rows sorted by field path, so callers and
// tests read the rows in record order.
func CensusRows() []Row {
	fields := make([]string, 0, len(fieldCensus))
	for field := range fieldCensus {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	rows := make([]Row, 0, len(fields))
	for _, field := range fields {
		rows = append(rows, Row{Field: field, Class: fieldCensus[field]})
	}
	return rows
}
