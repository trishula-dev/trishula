//go:build !linux

// cmd/shield darwin stub — the DoS runner host (TR-195, issue #237) is a
// linux process (the pinned maps + the kernel ban state live in linux).
// The real loop files under //go:build linux; this stub keeps the package
// buildable on non-linux hosts so the repo-wide build and vet stay clean.
package main

func main() {}
