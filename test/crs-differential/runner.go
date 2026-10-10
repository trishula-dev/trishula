// Package crsdifferential (TR-07b) is the CRS differential corpus harness
// [child of TR-07]: the reference CRS surface (the committed SecLang
// engine.conf + crs-setup + the @owasp_crs slice it includes, evaluated by
// internal/crs — the embedded-Coraza wrapper) meets a corpus that pins the
// observed rule-id sets per synthesized request (go-ftw SHAPE, hermetic:
// corpus + configs are go:embed'ed, no network, no cluster).
//
// Two stages, one gate:
//
//   - reference: internal/crs (Coraza wrapper) loads the committed
//     engine.conf slice; every corpus request is evaluated and projected
//     into per-phase rule-id sets + interruption evidence.
//   - engine-mirror: a small in-package evaluator asserts the corpus
//     expectations DIRECTLY against the reference verdicts (the latched
//     S2 ladder slot is NOT wired into the engine in this slice — the
//     mirror stage asserts crs.Evaluator parity only). A case passes when
//     the mirrored expectation (the pinned + seeded + off-seed rule-id
//     sets) equals the reference projection; zero unexplained deltas is
//     the parity gate, reported as parity X/N (target ≥ 90%).
//
// The corpus pinning semantics: match-id SETS per phase (order-free), with
// setup/echo ids pinned separately (README delta table), demotions and
// skip cases explicit.
package crsdifferential

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trishula-dev/trishula/internal/crs"
	"sigs.k8s.io/yaml"
)

//go:embed corpus/*.yaml
var corpusFS embed.FS

//go:embed all:testdata/seclang
var seclangFS embed.FS

// LoadReference loads the committed CRS slice from the embedded seclang
// filesystem into the reference evaluator: the directive tree is staged to
// a temp dir with its @owasp_crs sibling (the Coraza loader resolves
// Include paths on disk), then evaluated in-process by internal/crs.
func LoadReference() (crs.Evaluator, error) {
	dir, err := os.MkdirTemp("", "tr07b-seclang")
	if err != nil {
		return nil, err
	}
	if err := stageEmbeddedFS(seclangFS, "testdata/seclang", dir); err != nil {
		return nil, err
	}
	return crs.NewFromFile(filepath.Join(dir, "engine.conf"))
}

// LoadCorpus loads every embedded corpus case (corpus/*.yaml) in name
// order. A case that fails schema validation fails the whole load (a
// malformed corpus case is a harness bug, never a silent skip).
func LoadCorpus() (Corpus, error) {
	entries, err := corpusFS.ReadDir("corpus")
	if err != nil {
		return Corpus{}, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	cases := make([]Case, 0, len(names))
	for _, n := range names {
		b, err := corpusFS.ReadFile("corpus/" + n)
		if err != nil {
			return Corpus{}, err
		}
		var c Case
		if err := yaml.UnmarshalStrict(b, &c); err != nil {
			return Corpus{}, fmt.Errorf("corpus case %s: %w", n, err)
		}
		if c.Name == "" {
			return Corpus{}, fmt.Errorf("corpus case %s: empty name", n)
		}
		if c.Request.Method == "" || c.Request.URI == "" {
			return Corpus{}, fmt.Errorf("corpus case %s: request.method/uri required", n)
		}
		cases = append(cases, c)
	}
	return Corpus{Cases: cases}, nil
}

// stageEmbeddedFS materializes an embed.FS subtree (base) onto disk under
// dir (same relative paths), so directive Include lines resolve.
func stageEmbeddedFS(fsys embed.FS, base, dir string) error {
	return fs.WalkDir(fsys, base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := fsys.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// Corpus is the loaded case list (name order).
type Corpus struct {
	Cases []Case `json:"cases"`
}

// Case is one corpus entry (go-ftw SHAPE: name + request + expect).
type Case struct {
	Name    string  `json:"name"`
	Surface string  `json:"surface"`
	Skipped bool    `json:"skipped,omitempty"`
	Skip    string  `json:"skip,omitempty"`
	Request Request `json:"request"`
	Expect  Expect  `json:"expect"`
}

// Request is the synthesized CRS request (method/line/headers/body; the
// corpus pins URI/QS/UA/Referer/Cookie/form-body surfaces only).
type Request struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Version string            `json:"version"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

// Expect is the expectation the engine-mirror stage asserts (all optional:
// an empty expect is the clean-request shape — noise ids pinned separately).
type Expect struct {
	// Phase1Pinned are the setup-echo ids pinned per case (README).
	Phase1Pinned []int `json:"phase1_pinned,omitempty"`
	// P1941010 asserts the 941010 demotion surfaced a phase-1 marker.
	P1941010 bool `json:"p1_941010,omitempty"`
	// Phase2Seed are the seeded attack ids the mirror pins.
	Phase2Seed []int `json:"phase2_seed,omitempty"`
	// Phase2Offseed are the observed off-seed ids (live-probe evidence,
	// README table) — the mirror pins them as reference-observed.
	Phase2Offseed []int `json:"phase2_offseed,omitempty"`
}
