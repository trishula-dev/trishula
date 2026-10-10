package positive

import (
	"path/filepath"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// TestLoadPolicyRepoFixture loads the repo's schema fixture through the
// real loader — the exact bytes the operator story hands the gate.
func TestLoadPolicyRepoFixture(t *testing.T) {
	pol, err := LoadPolicy(filepath.Join("testdata", "openapi-chat.yaml"))
	if err != nil {
		t.Fatalf("load %s: %v", "openapi-chat.yaml", err)
	}
	if pol.Default != ladder.ActionAllow {
		t.Fatalf("policy default = %q, want the fail-open allow (v0)", pol.Default)
	}
	if s := pol.match("/v1/chat/completions"); s == nil || s.typ != "object" {
		t.Fatalf("route schema = %+v, want a compiled object schema", s)
	}
	if s := pol.match("/other"); s != nil {
		t.Fatalf("unmatched route returned %v, want nil", s)
	}
}
