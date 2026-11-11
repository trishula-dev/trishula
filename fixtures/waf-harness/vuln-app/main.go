// fixtures/waf-harness/vuln-app — the deliberately SQLi-vulnerable fixture
// app of the TR-205 WAF harness (issue #289). One stdlib Go server, no
// third-party imports: the fixture image builds from the PR checkout in-job.
//
// The fixture set (issue #289, item 3) carries one SQLi-vulnerable app and
// one benign traffic app. This process is the vulnerable member: the
// /search route builds its data statement by string concatenation, so a
// UNION probe in the query reaches the statement. The store stays in
// memory; the fixture never touches a real database. The engine fronts
// this app and enforces the waf-harness-gate policy on the route.
package main

import (
	"fmt"
	"log"
	"net/http"
)

// stmt builds the statement the route would feed a SQL store. The
// concatenation is the deliberate defect: a raw query string reaches the
// statement unparametrized. The harness records the statement instead of
// running it.
func stmt(q string) string {
	return "SELECT id, name FROM items WHERE q = '" + q + "'"
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "vuln-app home: the SQLi-fixture app serves")
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "prepared statement: %s\n", stmt(q))
	})
	addr := "0.0.0.0:8080"
	log.Printf("vuln-app listens on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
