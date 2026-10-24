package cuegen

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenArtefactsMatchCUE re-derives every artefact through the CUE Go
// API and compares against the committed bytes. This is the golden-diff
// gate's in-repo form: the cue-gate workflow runs the same comparison as a
// `go run ./cmd/cuegen` + `git diff --exit-code` step (TR-46 exit criterion:
// the golden gate rejects hand edits).
func TestGoldenArtefactsMatchCUE(t *testing.T) {
	outs, err := Plan(root(t))
	if err != nil {
		t.Fatalf("derive plan: %v", err)
	}
	if len(outs) == 0 {
		t.Fatal("the derivation plan is empty")
	}
	for _, o := range outs {
		t.Run(o.Path, func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join(root(t), filepath.FromSlash(o.Path)))
			if err != nil {
				t.Fatalf("read committed %s (is the artefact generated?): %v", o.Path, err)
			}
			if !bytes.Equal(bytes.TrimRight(got, "\n"), bytes.TrimRight(o.Bytes, "\n")) {
				t.Errorf("%s diverged from its CUE definition (hand edit or stale derivation): committed %d bytes, derived %d bytes", o.Path, len(got), len(o.Bytes))
			}
		})
	}
}
