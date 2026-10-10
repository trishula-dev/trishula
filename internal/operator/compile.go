package operator

// Package operator is the control-plane side of §8: it compiles
// trishula.security CRDs into the bundles the engine loads. TR-08b
// carries the in-process compile→load round-trip for WAFPolicy; the
// CRD watch/reconcile loop is TR-08c (no cluster calls here).
//
// TR-08b GREEN work pending on this file:
//   - Compile(policy v1alpha1.WAFPolicy) (Bundle, error)
//   - Load(bundle Bundle) (*Eval, error)
//   - the Eval verdict surface over cel.Request
// See compile_test.go for the observed RED contract.
