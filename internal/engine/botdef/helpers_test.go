package botdef

import "strings"

// lower is the ASCII lowercaser for header names (h1 names are ASCII; a
// non-ASCII byte passes through — normalization is deliberately narrow).
func lower(s string) string { return strings.ToLower(s) }
