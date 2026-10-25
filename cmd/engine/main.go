// TR-06 (issue #6) — minimal transparent reverse proxy for the engine host.
// Proves the v1 integration posture (the spec's reference walkthrough, variant A): behind the
// gateway the engine is a plain Gateway API backend forwarding transparently
// to the upstream pool — the gateway selects the engine Service exactly as
// it would select any backend; endpoint selection downstream of the engine
// is ordinary Service balancing.
//
// TR-08c (issue #76, M9) — the bundle leg: with --bundle, the engine Loads
// the operator's bundle (internal/operator, wire format v1) and consults it
// in the proxy handler BEFORE forwarding (the DX charter's consult step 1: "the engine consults
// the loaded bundle"): a decided request is answered by the engine, not
// the upstream. Without --bundle the handler is the unchanged transparent
// proxy (the engine stays a Gateway API citizen).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
	otel "github.com/trishula-dev/trishula/internal/engine/otel"
	"github.com/trishula-dev/trishula/internal/operator"
)

// hopHeader marks responses served through the engine hop so the DX1 lab
// (lab/dx1) can produce hop-by-hop evidence.
const hopHeader = "X-Trishula-Hop"

// bundleBox holds the consulted bundle state: nil eval = transparent. The
// reload loop swaps the eval under the lock; the handler reads it per
// request (the box also dedups reloads to the last successfully loaded
// bytes).
type bundleBox struct {
	mu     sync.RWMutex
	eval   *operator.Eval
	loaded []byte // last successfully loaded bundle bytes (reload dedup)
	// pipe (TR-195 leaf 4, issue #237): the verdict pipeline. Nil = no
	// emit (the transparent proxy and the tests that need no signals).
	// Non-nil = every consult decision emits the correlated verdict triad,
	// and a ban decision emits the trishula.ban record with the signature.
	pipe *otel.Pipeline
}

func (b *bundleBox) get() *operator.Eval {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.eval
}

func (b *bundleBox) same(data []byte) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return string(b.loaded) == string(data) && b.eval != nil
}

func (b *bundleBox) set(data []byte, e *operator.Eval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eval, b.loaded = e, data
}

// loadBundle decodes + loads bundle bytes (operator wire format v1).
func loadBundle(data []byte) (*operator.Eval, error) {
	var b operator.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("bundle decode: %w", err)
	}
	e, err := operator.Load(b)
	if err != nil {
		return nil, fmt.Errorf("bundle load: %w (tampered, corrupt, or uncompilable — refusing)", err)
	}
	return e, nil
}

// startBundlePolling polls path for bundle bytes: first presence = consult
// activated, content change = reloaded, corrupt content = keep previous and
// log (fail conservative — the previous verdicts stand). Process-lifetime
// loop (the lab's engine never exits on reload).
func startBundlePolling(ctx context.Context, path string, box *bundleBox, tick time.Duration) {
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				data, err := os.ReadFile(path)
				if err != nil {
					continue // absent/flaky read: consult stays as-is
				}
				if box.same(data) {
					continue
				}
				e, err := loadBundle(data)
				if err != nil {
					log.Printf("engine: bundle %s NOT reloaded: %v (previous bundle stands)", path, err)
					continue
				}
				box.set(data, e)
				log.Printf("engine: bundle loaded (%d rule packs) — consult active", len(e.EvalRulePacks()))
			}
		}
	}()
}

// banEvidencePath (TR-195 leaf 1): the direct would-ban JSONL sink path.
// Empty (the default) = the evidence log stays in the engine log (the
// enforcer's file-tail reads it in leaf 2 when the flag is set). Fail-open:
// a sink write error never affects the 403 already decided.
var banEvidencePath string

func recordDirectBan(d operator.Decision, r *http.Request) rateban.BanEvidence {
	key := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		key = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	atSec := time.Now().Unix()
	note := rateban.DirectBanNote(r.Method, r.URL.Path, d.RuleID)
	rec := rateban.DirectBan(key, d.RuleID, atSec, note)
	rec.OSig = &rateban.DoSSig{Class: "manual-rule", Paths: []string{r.URL.Path}}
	if banEvidencePath == "" {
		log.Printf("engine: direct would-ban (no evidence file set): %+v", rec)
		return rec
	}
	line, err := json.Marshal(rec)
	if err != nil {
		log.Printf("engine: direct would-ban marshal: %v", err)
		return rec
	}
	f, err := os.OpenFile(banEvidencePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("engine: direct would-ban open %s: %v (fail open)", banEvidencePath, err)
		return rec
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("engine: direct would-ban write: %v (fail open)", err)
	}
	return rec
}

// emitConsultSignals publishes one consult decision to the verdict
// pipeline (TR-195 leaf 4, issue #237): the triad (span, metric, log) with
// the verdict attributes, and for a ban decision the additional
// trishula.ban record (ban key, tier, score, reasons, signature). Nil
// pipe = no emit. A failed emit logs and continues (observability is a
// receipt surface; it never blocks the request).
func emitConsultSignals(box *bundleBox, r *http.Request, d operator.Decision, decisionWord string, banRec *rateban.BanEvidence) {
	if box == nil || box.pipe == nil {
		return
	}
	rid, ok := otel.RequestIDFromContext(r.Context())
	if !ok || rid == "" {
		rid = r.Header.Get(otel.HeaderRequestID)
	}
	if rid == "" {
		rid = otel.RequestIDFromContextOrGenerate(r.Context())
	}
	ctx := otel.ContextWithRequestID(r.Context(), rid)
	tx := &ingest.TxContext{Metadata: map[string]string{otel.MetaPathHint: r.URL.Path}}
	action := ladderAction(decisionWord)
	v := &ladder.Verdict{
		Action: action,
		Phase:  ladder.PhaseRequestHeaders,
	}
	if d.RuleID != "" {
		v.Rules = []ladder.RuleID{ladder.RuleID(d.RuleID)}
	}
	if banRec != nil && banRec.OSig != nil {
		sig := *banRec.OSig
		v.DosSig = &sig
	}
	if _, err := box.pipe.Emit(ctx, tx, v); err != nil {
		log.Printf("engine: verdict emit error (the decision stands): %v", err)
	}
	if banRec != nil {
		if err := box.pipe.EmitBan(*banRec); err != nil {
			log.Printf("engine: ban emit error (the decision stands): %v", err)
		}
	}
}

// ladderAction maps the consult decision word to the ladder action
// vocabulary (the verdict schema's action values).
func ladderAction(word string) ladder.Action {
	switch word {
	case "pass":
		return ladder.ActionAllow
	case "log":
		return ladder.ActionLog
	case "challenge":
		return ladder.ActionChallenge
	case "ban":
		return ladder.ActionBan
	default:
		return ladder.ActionBlock
	}
}

// newEngineHandler builds the engine host: /healthz answers ok engine-local
// (it must not reach the upstream); every other path is transparently
// proxied to the upstream. hop, when non-empty, is echoed on responses as
// X-Trishula-Hop. This is the v0 no-bundle shape (TR-06 contract).
func newEngineHandler(upstream, hop string) http.Handler {
	return newEngineHandlerWithBox(upstream, hop, &bundleBox{})
}

// newEngineHandlerWithBundle builds the engine host with explicit bundle
// bytes (the load-at-boot shape): nil keeps the pure transparent proxy;
// non-nil bytes load BEFORE any request is served — a failing bundle is a
// constructor error (fail closed at boot, never proxy unaudited).
func newEngineHandlerWithBundle(upstream, hop string, bundle []byte, pipe *otel.Pipeline) (http.Handler, error) {
	box := &bundleBox{pipe: pipe}
	if bundle != nil {
		e, err := loadBundle(bundle)
		if err != nil {
			return nil, fmt.Errorf("engine: %w", err)
		}
		box.set(bundle, e)
	}
	return newEngineHandlerWithBox(upstream, hop, box), nil
}

// newEngineHandlerWithBundlePath builds the engine host with a polled
// bundle path (the hot-reload shape): consult activates on the file's
// first valid content, reloads on change, keeps the previous bundle on a
// corrupt reload.
func newEngineHandlerWithBundlePath(ctx context.Context, upstream, hop, path string, tick time.Duration, pipe *otel.Pipeline) (http.Handler, *bundleBox) {
	box := &bundleBox{pipe: pipe}
	if data, err := os.ReadFile(path); err == nil {
		if e, err := loadBundle(data); err == nil {
			box.set(data, e)
			log.Printf("engine: bundle loaded (%d rule packs) — consult active", len(e.EvalRulePacks()))
		} else {
			log.Printf("engine: bundle at %s rejected at boot, polling for valid content: %v", path, err)
		}
	} else {
		log.Printf("engine: no bundle at %s yet — consult inactive (transparent), polling", path)
	}
	startBundlePolling(ctx, path, box, tick)
	return newEngineHandlerWithBox(upstream, hop, box), box
}

// newEngineHandlerWithBox is the handler core: the TR-06 proxy plus the
// TR-08c consult (nil eval in the box = the pure transparent proxy).
func newEngineHandlerWithBox(upstream, hop string, box *bundleBox) http.Handler {
	target, err := url.Parse(upstream)
	if err != nil {
		panic(fmt.Sprintf("engine: invalid upstream URL %q: %v", upstream, err))
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// Transparent: upstream transport failures surface as 502, never as
	// engine-local panics crashing the host.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("engine: upstream error for %s %s: %v", r.Method, r.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if consult := box.get(); consult != nil {
			decision, err := consult.Decide(celRequestView(r))
			if err != nil {
				// Fail safe (the spec's CEL rules): a deciding bundle erroring is state
				// corruption; the fail-closed answer is deny.
				log.Printf("engine: consult error for %s %s: %v", r.Method, r.URL.Path, err)
				w.Header().Set(hopHeader, "engine")
				w.Header().Set("X-Trishula-Decision", "error")
				http.Error(w, "engine consult error", http.StatusForbidden)
				return
			}
			w.Header().Set(hopHeader, "engine")
			decisionWord := string(decision.Action)
			var banRec *rateban.BanEvidence
			if decision.BanDirect {
				// TR-195 (issue #237): the manual ban names itself. The
				// response reads decision=ban + the owning rule; the
				// direct would-ban record joins the evidence stream (the
				// enforcer's kernel-write input; the receipt trail).
				decisionWord = "ban"
				rec := recordDirectBan(decision, r)
				banRec = &rec
			}
			emitConsultSignals(box, r, decision, decisionWord, banRec)
			w.Header().Set("X-Trishula-Decision", decisionWord)
			if decision.RuleID != "" {
				w.Header().Set("X-Trishula-Rule", decision.RuleID)
			}
			log.Printf("engine: decision %s (rule=%s) for %s %s", decisionWord, decision.RuleID, r.Method, r.URL.Path)
			if decision.Action == "block" {
				verb := "blocked"
				if decision.BanDirect {
					verb = "banned"
				}
				http.Error(w, verb+" by "+decision.RuleID, http.StatusForbidden)
				return
			}
			// log/pass/challenge/no-match: forward (v0 consult surface;
			// the challenge flow rides a later slice).
		}
		if hop != "" {
			w.Header().Set(hopHeader, hop)
		}
		proxy.ServeHTTP(w, r)
	})
}

// isReceiveMode reports whether argv carries the -receive-bundle mode
// (scanned before flag.Parse: it is a run mode, not a server flag).
func isReceiveMode(argv []string) (path string, ok bool) {
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-receive-bundle", "--receive-bundle":
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", true
		}
	}
	return "", false
}

// receiveBundle writes stdin's bytes to path atomically (tmp+rename) and
// reports the byte count — the lab's kubectl-exec delivery into the
// running engine's polled path.
func receiveBundle(path string, in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("receive: stdin: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("receive: stdin was empty")
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("receive: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("receive: rename -> %s: %w", path, err)
	}
	fmt.Fprintf(out, "bundle-received bytes=%d path=%s\n", len(data), filepath.Clean(path))
	return nil
}

// celRequestView projects the inbound request into the spec's structured
// view the CEL rules evaluate (seed scope: method, path with query
// stripped, the raw query string; rate_windows arrive with the rate-
// accounting slice). Query keys decode loosely via RawQuery (the rules'
// `request.query` contract: the raw query as sent).
func celRequestView(r *http.Request) (req cel.Request) {
	req.Method = r.Method
	req.Path = r.URL.Path
	req.Query = r.URL.RawQuery
	return req
}

func main() {
	if path, _ := isReceiveMode(os.Args[1:]); path != "" {
		if err := receiveBundle(path, os.Stdin, os.Stdout); err != nil {
			log.Fatalf("engine: -receive-bundle: %v", err)
		}
		return
	}
	listen := flag.String("listen", ":8080", "listen address of the engine host")
	upstream := flag.String("upstream", "", "upstream URL the engine transparently forwards to (required)")
	hop := flag.String("hop", "engine", "value for the X-Trishula-Hop response header (empty omits it)")
	bundlePath := flag.String("bundle", "", "path the operator's bundle JSON is loaded from (internal/operator wire format v1); first valid content activates the consult, changes hot-reload (TR-08c)")
	tlsCert := flag.String("tls-cert", "", "cert PEM to terminate TLS on the engine listener (TR-34 secondary mode, feature-gated; requires -tls-key; off = the default gateway-owned termination)")
	banEvidence := flag.String("ban-evidence", "", "JSONL path the manual ban-rule would-bans append to (TR-195 leaf 1; empty = the evidence stays in the engine log)")
	tlsKey := flag.String("tls-key", "", "key PEM for -tls-cert (TR-34 secondary mode)")
	noOtel := flag.Bool("no-otel", false, "disable the verdict pipeline (the consult signals; TR-195 leaf 4)")
	flag.Parse()
	banEvidencePath = *banEvidence

	var pipe *otel.Pipeline
	if !*noOtel {
		p, err := otel.New(otel.Config{ServiceName: "trishula-engine"})
		if err != nil {
			log.Fatalf("engine: verdict pipeline: %v", err)
		}
		pipe = p
	}

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "engine: --upstream is required")
		flag.Usage()
		os.Exit(2)
	}
	var handler http.Handler
	if *bundlePath != "" {
		handler, _ = newEngineHandlerWithBundlePath(context.Background(), *upstream, *hop, *bundlePath, 200*time.Millisecond, pipe)
	} else {
		handler = newEngineHandler(*upstream, *hop)
	}
	addr := *listen
	ln, err := engineListener(addr, *tlsCert, *tlsKey)
	if err != nil {
		log.Fatal(err)
	}
	if *tlsCert != "" {
		log.Printf("engine: TLS termination active on %s (TR-34 secondary mode; the default stays gateway-owned termination)", addr)
	} else {
		log.Printf("engine: listening on %s (plaintext), forwarding to %s", addr, *upstream)
	}
	srv := &http.Server{Handler: handler}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
