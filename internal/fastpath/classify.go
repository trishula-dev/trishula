package fastpath

import (
	"errors"
)

// ErrUnknownField reports a field outside the census. The classifier fails
// closed: an unlisted field never compiles, and a silent slow-path default
// would forge a record row.
var ErrUnknownField = errors.New("fastpath: field outside the census")

// fieldCensus maps one WAFPolicy field path to its compile class. The paths
// follow the CRD's JSON tree: the spec leaves of api/v1alpha1 (the TR-08a v0
// surface, docs/design/socket-plane/4-compiler-census.md §3) plus the two
// metadata fields the compile stamps.
//
// The status subresource stays out of the map by design: the record's
// compile-split section owns status, not this skeleton's classifier.
//
// stub: RED (TR-40a) — the census rows land with the GREEN commit; the
// coverage test walks the CRD spec tree against this map.
var fieldCensus = map[string]Class{}

// Classify returns the compile class of one WAFPolicy field. The field names
// in the census's path form ("spec.defaultAction", "metadata.namespace").
// Unknown fields fail closed with ErrUnknownField.
//
// stub: RED (TR-40a) — the census lookup lands with the GREEN commit.
func Classify(field string) (Class, error) {
	return "", ErrUnknownField
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
//
// stub: RED (TR-40a) — the row list lands with the GREEN commit.
func CensusRows() []Row {
	return nil
}
