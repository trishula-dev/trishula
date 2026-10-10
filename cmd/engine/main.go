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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/operator"
)

// hopHeader marks responses served through the engine hop so the DX1 lab
// (lab/dx1) can produce hop-by-hop evidence.
const hopHeader = "X-Trishula-Hop"

// newEngineHandler builds the engine host: /healthz answers ok engine-local
// (it must not reach the upstream); every other path is transparently
// proxied to the upstream. hop, when non-empty, is echoed on responses as
// X-Trishula-Hop. This is the v0 no-bundle shape (TR-06 contract).
func newEngineHandler(upstream, hop string) http.Handler {
	h, err := newEngineHandlerWithBundle(upstream, hop, nil)
	if err != nil {
		panic(fmt.Sprintf("engine: %v", err))
	}
	return h
}

// newEngineHandlerWithBundle builds the engine host with an optional
// bundle: nil keeps the pure transparent proxy; non-nil bytes are the
// operator's bundle JSON, loaded (operator.Load: digest-re-verified, rules
// compile-checked) BEFORE any request is served. A bundle that fails load
// is a constructor error (fail closed at boot — never proxy unaudited).
func newEngineHandlerWithBundle(upstream, hop string, bundle []byte) (http.Handler, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("engine: invalid upstream URL %q: %w", upstream, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// Transparent: upstream transport failures surface as 502, never as
	// engine-local panics crashing the host.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("engine: upstream error for %s %s: %v", r.Method, r.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
	}
	var consult *operator.Eval
	if bundle != nil {
		var b operator.Bundle
		if err := json.Unmarshal(bundle, &b); err != nil {
			return nil, fmt.Errorf("engine: bundle decode: %w", err)
		}
		consult, err = operator.Load(b)
		if err != nil {
			return nil, fmt.Errorf("engine: bundle load: %w", err)
		}
		log.Printf("engine: bundle loaded (%d rule packs) — consult active", len(b.RulePacks))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if consult != nil {
			reqView := celRequestView(r)
			decision, err := consult.Decide(reqView)
			if err != nil {
				// Fail safe (§11.3): an evaluating bundle erroring is a
				// decode/state corruption; with nothing to consult the
				// fail-closed answer is deny.
				log.Printf("engine: consult error for %s %s: %v", r.Method, r.URL.Path, err)
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
	}), nil
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
	listen := flag.String("listen", ":8080", "listen address of the engine host")
	upstream := flag.String("upstream", "", "upstream URL the engine transparently forwards to (required)")
	hop := flag.String("hop", "engine", "value for the X-Trishula-Hop response header (empty omits it)")
	bundlePath := flag.String("bundle", "", "path to the operator bundle JSON (internal/operator wire format v1); loads and consults before forwarding (TR-08c)")
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "engine: --upstream is required")
		flag.Usage()
		os.Exit(2)
	}
	var bundleBytes []byte
	if *bundlePath != "" {
		data, err := os.ReadFile(*bundlePath)
		if err != nil {
			log.Fatalf("engine: read --bundle %s: %v", *bundlePath, err)
		}
		bundleBytes = data
	}
	handler, err := newEngineHandlerWithBundle(*upstream, *hop, bundleBytes)
	if err != nil {
		log.Fatal(err)
	}
	addr := *listen
	log.Printf("engine: listening on %s, forwarding to %s", addr, *upstream)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}
