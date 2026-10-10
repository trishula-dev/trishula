// Package positive implements the §11.5 positive-security stage (ladder
// slot S4, TR-13): validate what a request IS before spending rungs on
// what it DOES — an OpenAPI 3.1 subset loaded once per route, then driven
// per request over the attached §11.3 view.
//
// v0 slice (TR-13a): the GREEN surface is
//   - Schema — the OpenAPI route schema (v0 subset, strict decode),
//   - LoadPolicy — schema + policy load from a document,
//   - RequestEvaluator.Evaluate — the per-request fragment
//     (ladder vocabulary; violations → ActionLog + diagnostics),
//   - RuleIDSchemaViolation — the S4 rule id.
//
// Response-side schema (the §11.5 exfiltration guard) is Phase 2 of the
// roadmap (§20.2); headers/query/path parameter validation are named
// v0.1 follow-ups. See README.md for the CRD plan.
package positive

// v0DiagnosticStubs pin the RED-state diagnostic surface (asserted
// exactly in positive_test.go; GREEN renders them from the validator).
var v0DiagnosticStubs = []string{
	"body.model: expected string, got number",
	"body.messages[1].role: required field \"role\" missing",
	"body.messages[2].role: value \"wheel\" not in enum [assistant system user]",
	"body.temperature: expected number, got string",
}

// v0RuleIDPending is GREEN's ladder.RuleID("positive:violation") site.
const v0RuleIDPending = "positive:violation"

// v0DefaultActionPending is GREEN's ladder.ActionLog fail-open default.
const v0DefaultActionPending = "log"
