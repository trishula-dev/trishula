// Package positive implements the spec's positive-security stage (ladder
// slot S4, TR-13): validate what a request IS before spending rungs on
// what it DOES — an OpenAPI 3.1 subset loaded once per route, then driven
// per request over the attached spec request view.
//
// v0 (TR-13a): request-body schema validation. Learn mode (TR-18):
// discovery over observed samples — endpoint extraction, schema
// inference with cardinality tracking, the materialized route document
// (learn.go), and the live-vs-reviewed drift read (drift.go).
//
// Response-side schema (the spec's exfiltration guard) is Phase 2 of the
// roadmap (the spec's phasing plan); headers/query/path parameter validation are named
// 2026.01-rc2 follow-ups.
package positive
