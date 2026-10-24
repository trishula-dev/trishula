package fastpath

// The route-template contract bounds (the census record's template
// contract, section 5). The compile and the loader share them: the compile
// fails closed past a bound, and the loader re-checks before it stages.
// One template carries one program. v1 carries no tail calls.

// RouteTemplateMaxEntries is the route-table bound. The map declares the
// same figure; a policy past it fails the compile.
const RouteTemplateMaxEntries = 8

// RouteTemplatePrefixMaxBytes is the per-prefix bound in bytes. The kernel
// key carries the same field width.
const RouteTemplatePrefixMaxBytes = 64

// The kernel-path action codes (the part-1 action primitives: forward,
// drop). The compile maps the CRD vocabulary onto them; the loader
// validates every staged code against this set.
const (
	// RouteTemplateActionForward passes the request on. It is the default
	// forward of the template contract.
	RouteTemplateActionForward uint8 = 0
	// RouteTemplateActionDrop drops the request at the fast path.
	RouteTemplateActionDrop uint8 = 1
)
