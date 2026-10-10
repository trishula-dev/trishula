// Package positive implements the §11.5 positive-security stage (ladder
// slot S4, TR-13): validate what a request IS before spending rungs on
// what it DOES — an OpenAPI 3.1 subset loaded once per route, then driven
// per request over the attached §11.3 view.
//
// v0 (TR-13a): request-body schema validation only. Response-side schema
// (the §11.5 exfiltration guard) is Phase 2 of the roadmap (§20.2);
// headers/query/path parameter validation are named v0.1 follow-ups.
package positive
