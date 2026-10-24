// Package fastpath carries the TR-40a compiler skeleton: the supported-subset
// census classes of the WAFPolicy surface plus the field classifier that
// splits each field between the kernel fast path and the engine slow path.
//
// The classes carry the [§9.9] kernel-offloadable subset: JWT HS256 authz
// (issuer/audience claims), RBAC allowlists (source IPs, ports, paths), route
// marking, telemetry counters, header mutation. Every other class routes to
// the slow path (the engine / ext_proc route) with no claim of enforcement.
//
// Two honesty rules pin the skeleton:
//
//   - The census is closed. Classify fails closed on a field outside the
//     census; a new WAFPolicy surface field takes its census row first, and
//     the coverage test walks the CRD spec tree to enforce the row set.
//   - The gate owns eligibility. JWT HS256 sits inside the subset, but the
//     kernel-module record (docs/design/socket-plane/1-mechanism.md) keeps
//     its hash/encode gate locked at the tracked evaluation, so its verdict
//     stays gate-locked.
//
// Nothing here compiles or loads a kernel program. Template instantiation,
// the bpf2go build beside the shield build and the compile-split status
// surface land with the later TR-40 leaves (issue #52). The [§9.9] contract
// holds: tracked evaluation, not a v1 commitment. The design record:
// docs/design/socket-plane/4-compiler-census.md.
//
// [§9.9]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment
package fastpath

// Class is one compile class a WAFPolicy field lands in.
//
// The five subset classes carry the kernel-offloadable set of the spec's
// socket-plane fast-path section (the package comment carries the [§9.9]
// link); ClassSlowPath collects everything else. The classes carry vocabulary
// only — the classifier (classify.go) assigns them per field path.
type Class string

// The census classes (the record's class set:
// docs/design/socket-plane/4-compiler-census.md).
const (
	// ClassJWTAuthz is JWT HS256 authorization over issuer/audience claims.
	// Kernel-eligible; the hash/encode gate stays locked at the tracked
	// evaluation.
	ClassJWTAuthz Class = "jwt_authz"
	// ClassRBACAllowlist is the allowlist class over source IPs, ports and paths.
	ClassRBACAllowlist Class = "rbac_allowlist"
	// ClassRoute is the route-marking class.
	ClassRoute Class = "route"
	// ClassTelemetry is the counters class over the shared map state.
	ClassTelemetry Class = "telemetry"
	// ClassHeaderMutation is the header mutation class.
	ClassHeaderMutation Class = "header_mutation"
	// ClassSlowPath collects every class outside the kernel-offloadable
	// subset. A slow-path field carries no kernel enforcement claim.
	ClassSlowPath Class = "slow_path"
)

// String returns the class name.
func (c Class) String() string { return string(c) }

// KernelEligible reports membership in the kernel-offloadable subset (the
// [§9.9] link lives in the package comment): the five header-class classes
// the record names. ClassSlowPath sits outside.
func (c Class) KernelEligible() bool {
	switch c {
	case ClassJWTAuthz, ClassRBACAllowlist, ClassRoute, ClassTelemetry, ClassHeaderMutation:
		return true
	default:
		return false
	}
}

// GateState is the hash/encode kernel-coverage gate state. The mechanism
// record (docs/design/socket-plane/1-mechanism.md) owns the gate: it skips
// the gated classes while hash/encode kfunc coverage is absent on the tracked
// kernels, and it re-reads the gate when the kernel moves upstream.
type GateState string

// The gate states.
const (
	// GateOpen lets a kernel-eligible class compile to the kernel path.
	GateOpen GateState = "open"
	// GateLocked routes a kernel-eligible class to the slow path; the gated
	// primitive (hash, encode) is absent from the eBPF runtime.
	GateLocked GateState = "locked"
)

// String returns the gate-state name.
func (g GateState) String() string { return string(g) }

// Gate reports the hash/encode kernel-coverage gate state of the class.
// ClassJWTAuthz stays locked at the tracked evaluation; the other classes sit
// open. The gate question decides inside the subset only — ClassSlowPath
// reads open and never reaches a kernel artifact.
func (c Class) Gate() GateState {
	if c == ClassJWTAuthz {
		return GateLocked
	}
	return GateOpen
}

// Verdict is the compile-split value the honesty surface records per field:
// one value per field, kernel or slow route or a locked gate, never a
// wholesale enforced claim. The record's compile-split design carries the
// surface (docs/design/socket-plane/4-compiler-census.md).
type Verdict string

// The split values.
const (
	// VerdictKernel marks a field whose compile produces a kernel program.
	VerdictKernel Verdict = "kernel"
	// VerdictSlowPath marks a field routed to the engine / ext_proc slow path.
	VerdictSlowPath Verdict = "slow-path"
	// VerdictGateLocked marks a kernel-eligible class whose gate stays locked.
	VerdictGateLocked Verdict = "gate-locked"
)

// String returns the verdict name.
func (v Verdict) String() string { return string(v) }

// Verdict reports the compile-split value of the class: outside the subset →
// the slow path; inside with a locked gate → gate-locked; inside with an open
// gate → kernel.
func (c Class) Verdict() Verdict {
	if !c.KernelEligible() {
		return VerdictSlowPath
	}
	if c.Gate() == GateLocked {
		return VerdictGateLocked
	}
	return VerdictKernel
}
