package positive

// GREEN (TR-13a) fills this file: validate(view) against the loaded
// schema — type checks, required-field presence, enum membership,
// maxLength/pattern — producing diagnostics that name the violated field
// path, plus the ladder-fragment wrapper.

// v0FragmentPending is the RED-state type-site placeholder (GREEN
// replaces this with the real Diagnostic/Fragment types).
type v0FragmentPending = struct{}
