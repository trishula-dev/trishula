package operator

// TR-08c (issue #76) — the embedded seed-pack copy
// (internal/operator/seed_pack.yaml, the go:embed source the deployed
// operator compiles from) must stay byte-identical to the canonical
// rules/cel/seed.yaml. A diverged copy would compile bundles whose default
// CEL plane differs between test and deployed builds.

import (
	"bytes"
	"os"
	"testing"
)

func TestEmbeddedSeedPackMatchesCanonicalFile(t *testing.T) {
	canonical, err := os.ReadFile(seedPackPath)
	if err != nil {
		t.Fatalf("read canonical seed pack: %v", err)
	}
	if !bytes.Equal(canonical, seedPackBytes) {
		t.Fatal("internal/operator/seed_pack.yaml diverged from rules/cel/seed.yaml — keep the embed byte-identical")
	}
	if len(seedPackBytes) == 0 {
		t.Fatal("the embed is empty; the deployed operator would fall back to a repo path it does not have")
	}
}
