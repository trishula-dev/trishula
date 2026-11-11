// fixtures/waf-harness/sqlfix-app — the genuinely SQLi-vulnerable sqlite
// fixture app of the TR-205 release WAF suite (issue #293, the #300 fix
// pass: the Greptile comment "target only prints queries" — the earlier
// vuln-app recorded the statement without running it, so a 0-injection
// sqlmap gate proved nothing).
//
// This process runs the statement. The /sql route concatenates the raw
// query into the SELECT against a seeded sqlite table and returns the
// rows, so an injection the engine misses both executes and answers.
// The store is a real database (modernc.org/sqlite, the pure-Go sqlite
// driver; NO cgo, so the scratch image build stays static). The
// seeded rows never change at run time; only the statement is
// attacker-controlled.
//
// The bundle: the calibration phase runs sqlmap DIRECTLY against this
// service (engine-less route) and expects at least one successful
// injection — the pass proof that the target can carry the gate. The
// gate phase runs the same scan through the engine instance
// (waf-harness-engine-sqlfix, manifests/sqlfix.yaml) and expects zero.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "modernc.org/sqlite" // the pure-Go sqlite driver (name "sqlite", NO cgo)
)

// openStore opens the driver database and seeds it. The file sits in the
// working directory (the scratch image ships no /tmp); one connection
// serializes the read-write traffic so a concurrent scan never reads a
// locked store. The schema plus the seeds re-apply idempotently on every
// start, so the run state is always the fixed set below.
func openStore() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:sqlfix.db?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT)`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_id ON users (id)`); err != nil {
		return nil, err
	}
	for _, row := range [][2]string{
		{"1", "alice"},
		{"2", "bob"},
		{"3", "carol"},
	} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO users (id, name) VALUES (?, ?)`,
			row[0], row[1]); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// injectableQuery builds the statement the /sql route would feed the
// store. The concatenation is the deliberate defect: the raw query
// parameter reaches the statement unparametrized.
func injectableQuery(q string) string {
	return "SELECT name FROM users WHERE id = '" + q + "'"
}

func main() {
	db, err := openStore()
	if err != nil {
		log.Fatalf("sqlfix-app: the store does not open: %v", err)
	}
	defer func() { _ = db.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "sqlfix-app home: the sqlite SQLi-fixture app serves")
	})
	mux.HandleFunc("/sql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		q := r.URL.Query().Get("q")
		query := injectableQuery(q)
		rows, err := db.Query(query)
		if err != nil {
			// The raw sqlmap probe surface: the store error text reaches
			// the response body, so error-based detection reads a real
			// signature.
			fmt.Fprintf(w, "sql error: %v\n", err)
			return
		}
		defer func() { _ = rows.Close() }()
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				fmt.Fprintf(w, "sql error: %v\n", err)
				return
			}
			names = append(names, name)
		}
		if err := rows.Err(); err != nil {
			fmt.Fprintf(w, "sql error: %v\n", err)
			return
		}
		fmt.Fprintf(w, "rows=%d\n", len(names))
		for _, n := range names {
			fmt.Fprintln(w, "name="+n)
		}
	})
	addr := "0.0.0.0:8080"
	log.Printf("sqlfix-app listens on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
