// TR-06 (issue #6) — minimal transparent reverse proxy for the engine host.
// Proves the v1 integration posture (PRD §10.3 variant A): behind the
// gateway the engine is a plain Gateway API backend forwarding transparently
// to the upstream pool — the gateway selects the engine Service exactly as
// it would select any backend; endpoint selection downstream of the engine
// is ordinary Service balancing.
//
// TR-08c (issue #76, M9) — the bundle leg: with --bundle, the engine Loads
// the operator's bundle (internal/operator, wire format v1) and consults it
// in the proxy handler BEFORE forwarding (§5.2 step 1: "the engine consults
// the loaded bundle"): a decided request is answered by the engine, not
// the upstream. Without --bundle the handler is the unchanged transparent
// proxy (the engine stays a Gateway API citizen).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/cel"
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
func newEngineHandlerWithBundle(upstream, hop string, bundle []byte) (http.Handler, error) {
	box := &bundleBox{}
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
func newEngineHandlerWithBundlePath(ctx context.Context, upstream, hop, path string, tick time.Duration) (http.Handler, *bundleBox) {
	box := &bundleBox{}
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
				// Fail safe (§11.3): a deciding bundle erroring is state
				// corruption; the fail-closed answer is deny.
				log.Printf("engine: consult error for %s %s: %v", r.Method, r.URL.Path, err)
				w.Header().Set(hopHeader, "engine")
				w.Header().Set("X-Trishula-Decision", "error")
				http.Error(w, "engine consult error", http.StatusForbidden)
				return
			}
			w.Header().Set(hopHeader, "engine")
			w.Header().Set("X-Trishula-Decision", string(decision.Action))
			if decision.RuleID != "" {
				w.Header().Set("X-Trishula-Rule", decision.RuleID)
			}
			log.Printf("engine: decision %s (rule=%s) for %s %s", decision.Action, decision.RuleID, r.Method, r.URL.Path)
			if decision.Action == "block" {
				http.Error(w, "blocked by "+decision.RuleID, http.StatusForbidden)
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

// celRequestView projects the inbound request into the §11.3 structured
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
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "engine: --upstream is required")
		flag.Usage()
		os.Exit(2)
	}
	var handler http.Handler
	if *bundlePath != "" {
		handler, _ = newEngineHandlerWithBundlePath(context.Background(), *upstream, *hop, *bundlePath, 200*time.Millisecond)
	} else {
		handler = newEngineHandler(*upstream, *hop)
	}
	addr := *listen
	log.Printf("engine: listening on %s, forwarding to %s", addr, *upstream)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}
