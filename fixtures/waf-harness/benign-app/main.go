// fixtures/waf-harness/benign-app — the benign traffic fixture app of the
// TR-205 WAF harness (issue #289). One stdlib Go server, no third-party
// imports: the fixture image builds from the PR checkout in-job.
//
// The fixture set (issue #289, item 3) carries one SQLi-vulnerable app and
// one benign traffic app. This process is the benign member: it serves a
// normal status page and a health route, and it accepts no query input.
// The harness probes it directly as the no-decision traffic leg.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// status is the fixed record the status route returns. The fixture serves
// normal traffic only; no route reads query input.
type status struct {
	App    string `json:"app"`
	Status string `json:"status"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(status{App: "benign-app", Status: "ok"})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	addr := "0.0.0.0:8080"
	log.Printf("benign-app listens on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
