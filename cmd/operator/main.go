// cmd/operator — trishula-operator (placeholder, TR-01): the deployed
// control-plane binary. TR-08c's DX1 lab slice drives the reconcile logic
// through the go test in the repo; the watch-loop operator that runs
// Reconcile against the live API server is a later TR-08 slice.
package main

import (
	_ "github.com/trishula-dev/trishula/api/v1alpha1"
	_ "github.com/trishula-dev/trishula/internal/operator"
)

func main() {}
