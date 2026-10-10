// TR-06 (issue #6) — minimal transparent reverse proxy for the engine host.
// Proves the v1 integration posture (PRD §10.3 variant A): behind the
// gateway the engine is a plain Gateway API backend forwarding transparently
// to the upstream pool — the gateway selects the engine Service exactly as
// it would select any backend; endpoint selection downstream of the engine
// is ordinary Service balancing. No CEL/ladder wiring in this slice.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

// hopHeader marks responses served through the engine hop so the DX1 lab
// (lab/dx1) can produce hop-by-hop evidence.
const hopHeader = "X-Trishula-Hop"

// newEngineHandler builds the engine host: /healthz answers ok engine-local
// (it must not reach the upstream); every other path is transparently
// proxied to the upstream. hop, when non-empty, is echoed on responses as
// X-Trishula-Hop.
func newEngineHandler(upstream, hop string) http.Handler {
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
		if hop != "" {
			w.Header().Set(hopHeader, hop)
		}
		proxy.ServeHTTP(w, r)
	})
}

func main() {
	listen := flag.String("listen", ":8080", "listen address of the engine host")
	upstream := flag.String("upstream", "", "upstream URL the engine transparently forwards to (required)")
	hop := flag.String("hop", "engine", "value for the X-Trishula-Hop response header (empty omits it)")
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "engine: --upstream is required")
		flag.Usage()
		os.Exit(2)
	}

	addr := *listen
	log.Printf("engine: listening on %s, forwarding to %s", addr, *upstream)
	if err := http.ListenAndServe(addr, newEngineHandler(*upstream, *hop)); err != nil {
		log.Fatal(err)
	}
}
