//go:build !shield_hook_spike

// The stub keeps `go build ./...`, `go vet ./...` and `go test ./...`
// green on every GOOS and every tag combination the other workflows use.
// The real probe (main.go in this package) needs linux plus the
// shield_hook_spike build tag and root — the spike workflow
// (.github/workflows/shield-hook-spike.yml) builds and runs it inside the
// privileged pod (issue #292).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "cmd/shield-hook-spike: this build excluded the probe (needs GOOS=linux and -tags shield_hook_spike); rebuild with that tag, as the spike workflow does (issue #292)")
	os.Exit(2)
}
