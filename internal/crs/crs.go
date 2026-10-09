package crs

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
)

// Package crs (TR-07 PR A): the embedded-Coraza CRS shadow evaluator —
// a SecLang directive file (CRS ruleset: crs-setup.conf.example + the
// PL1 profile) loaded once, CRS requests evaluated into shadow verdicts
// (per-phase match projections + interruption evidence). Verdicts are
// logged, NEVER enforced (PRD §5.15 shadow-first; §11 Coraza).

// PhaseRequestHeaders / PhaseRequestBody are the CRS request phases this
// slice evaluates (Coraza phase-1 / phase-2); response phases land with
// the response-side slice.
const (
	PhaseRequestHeaders = 1
	PhaseRequestBody    = 2
)

// Match is one rule contribution inside an evaluated phase (a Coraza
// MatchedRule projected: rule id, phase, disruptive flag).
type Match struct {
	RuleID     int
	Phase      int
	Disruptive bool
}

// Verdict is the shadow-verdict shape for one CRS request across both
// phases: per-phase matches plus the interruption evidence (a
// disruptive phase-2 deny leaves an interruption carrying the denying
// rule id and its HTTP status).
type Verdict struct {
	Phase1Matches []Match
	Phase2Matches []Match
	Interrupted   bool
	InterruptRule int
	InterruptStat int
}

// Options carry the per-request scope (request line, headers, body) plus
// the injected peer scope Coraza transactions are keyed on. The clock is
// not used by the SecLang run itself (no time-based rules in the seed
// snippet); it stamps the tx scope for parity/telemetry correlation.
type Options struct {
	Method  string
	URI     string
	Version string
	Headers map[string]string
	Body    []byte
	Client  netip.Addr
	Port    int
	Now     time.Time
}

// Evaluator is the shadow evaluation surface the parity harness drives:
// load once, evaluate many (thread-safe).
type Evaluator interface {
	Evaluate(opts Options) (Verdict, error)
}

// fileEvaluator runs SecLang rules over one CRS request through an
// embedded Coraza WAF instance. Matches are PROJECTED data, never
// enforcement: the walk always runs to the logging phase and the
// interruption is reported inside the Verdict (TestShadowMode).
type fileEvaluator struct {
	waf    coraza.WAF
	now    func() time.Time
	logger debuglog.Logger
}

// EvalOption is an evaluator-scope injection (testability: clock +
// logger; the request scope comes per Evaluate call).
type EvalOption func(*evalOptions)

type evalOptions struct {
	now    func() time.Time
	logger debuglog.Logger
}

// WithClock replaces the injected clock (default time.Now; the clock is
// not consumed by phase-1/2 SecLang rules in this slice — it stamps the
// parity/telemetry correlation surface).
func WithClock(now func() time.Time) EvalOption {
	return func(eo *evalOptions) { eo.now = now }
}

// WithLogger replaces the injected debuglog.Logger (default Noop: a
// silent run keeps host CI quiet; never a default logger).
func WithLogger(l debuglog.Logger) EvalOption {
	return func(eo *evalOptions) { eo.logger = l }
}

// NewFromFile loads a SecLang directive file (CRS ruleset:
// crs-setup.conf.example + the PL1 profile) into an evaluator. The file
// must parse clean: an unknown directive is a load error, never a silent
// skip (TestLoadError).
func NewFromFile(path string) (Evaluator, error) {
	return NewFromFileWithOptions(path)
}

// NewFromFileWithOptions is NewFromFile with evaluator-scope injections.
func NewFromFileWithOptions(path string, eopts ...EvalOption) (Evaluator, error) {
	eo := evalOptions{}
	for _, f := range eopts {
		f(&eo)
	}
	if eo.now == nil {
		eo.now = time.Now
	}
	if eo.logger == nil {
		eo.logger = debuglog.Noop()
	}
	debugLogger := eo.logger.WithLevel(debuglog.LevelNoLog)
	if path == "" {
		return nil, errors.New("crs: empty SecLang directive path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crs: read directive file: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("crs: empty SecLang directive file: %s", path)
	}
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(path).
		WithRequestBodyAccess().
		WithRequestBodyLimit(10 * 1024 * 1024).
		WithRequestBodyInMemoryLimit(1 * 1024 * 1024).
		WithDebugLogger(debugLogger)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("crs: build WAF from %s: %w", path, err)
	}
	return &fileEvaluator{waf: waf, now: eo.now, logger: debugLogger}, nil
}

// walk returns the raw Coraza evidence for one request: the phase-1 and
// phase-2 matched-rule lists (match order preserved) plus the
// interruption after phase 2.
func (e *fileEvaluator) walk(o Options) (matched []types.MatchedRule, interrupted bool, intRule, intStat int, err error) {
	if o.Version == "" {
		o.Version = "1.1"
	}
	if o.Client.IsValid() && o.Port == 0 {
		o.Port = 80
	}
	tw := e.waf.NewTransaction()
	defer tw.Close()

	serverHost, serverPort := "trishula.local", 80
	if host, ok := o.Headers["Host"]; ok && host != "" {
		serverHost, serverPort = splitHostPort(host)
	}
	tw.ProcessConnection(o.Client.String(), o.Port, serverHost, serverPort)
	if o.Now.IsZero() {
		o.Now = e.now()
	}
	tw.ProcessURI(o.URI, o.Method, o.Version)
	for k, v := range o.Headers {
		tw.AddRequestHeader(k, v)
	}
	if it := tw.ProcessRequestHeaders(); it != nil {
		interrupted, intRule, intStat = true, it.RuleID, it.Status
	}
	// Phase 2 runs UNCONDITIONALLY (unless phase 1 disrupted): the CRS
	// reference semantics evaluate 920230/921xxx/941xxx/942xxx phase-2
	// rules and the 949110 blocking evaluation for every request —
	// including body-less ones — so a body-less attack must still deny.
	// Without this, phase-2 rules silently no-op whenever no body was
	// written (ProcessRequestBody early-returns only inside the body
	// branch, never for body-less requests).
	if !interrupted && tw.IsRequestBodyAccessible() {
		if o.Body != nil {
			if _, _, werr := tw.WriteRequestBody(o.Body); werr != nil {
				return matched, interrupted, intRule, intStat, fmt.Errorf("crs: write request body: %w", werr)
			}
		}
		if it, berr := tw.ProcessRequestBody(); berr != nil {
			return matched, interrupted, intRule, intStat, fmt.Errorf("crs: process request body: %w", berr)
		} else if it != nil && !interrupted {
			interrupted, intRule, intStat = true, it.RuleID, it.Status
		}
	}
	// The logging phase closes the tx walk; matched rules are stable
	// evidence once it has run.
	tw.ProcessLogging()
	matched = tw.MatchedRules()
	return matched, interrupted, intRule, intStat, nil
}

// splitHostPort splits a Host header into server name + port (default
// 80 when no :port suffix is present).
func splitHostPort(host string) (string, int) {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			n := 0
			ok := true
			for _, c := range host[i+1:] {
				if c < '0' || c > '9' {
					ok = false
					break
				}
				n = n*10 + int(c-'0')
			}
			if ok && n > 0 {
				return host[:i], n
			}
		}
		if host[i] == ']' { // IPv6 literal: no port suffix parse
			return host, 80
		}
	}
	return host, 80
}

// Evaluate runs the walk and projects the evidence into the shadow
// Verdict: per-phase Match lists (match order preserved) plus the
// interruption. Phase-2 denies surface as Verdict.Interrupted — an
// enforcement-shaped outcome is DATA here (the §5.15 shadow posture),
// never a call error.
func (e *fileEvaluator) Evaluate(o Options) (Verdict, error) {
	matched, interrupted, intRule, intStat, err := e.walk(o)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Interrupted: interrupted, InterruptRule: intRule, InterruptStat: intStat}
	for _, mr := range matched {
		m := Match{
			RuleID:     mr.Rule().ID(),
			Phase:      int(mr.Rule().Phase()),
			Disruptive: mr.Disruptive(),
		}
		switch m.Phase {
		case PhaseRequestHeaders:
			v.Phase1Matches = append(v.Phase1Matches, m)
		case PhaseRequestBody:
			v.Phase2Matches = append(v.Phase2Matches, m)
		}
	}
	return v, nil
}
