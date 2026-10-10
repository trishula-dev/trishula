// Package-level wire surface (TR-11): the stdlib http middleware mounting
// the verdict pipeline. RED state: symbols declared, body pending GREEN.
package otel

import (
	"context"
	"net/http"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// HeaderRequestID is the inbound header the middleware adopts verbatim.
const HeaderRequestID = "X-Request-ID"

// Emitter is the engine callback the middleware drives
// (the engine host evaluates the ladder and returns here).
type Emitter interface {
	Emit(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) error
}

// Middleware mounts the verdict pipeline: it resolves the request id
// (header, else generated), injects it into the request context, starts the
// request span and calls the engine through emit. RED: returns unwired.
func Middleware(p *Pipeline, next Emitter) http.Handler { return nil }

// wireHandler is the concrete handler (tests poke it).
type wireHandler struct {
	emitForTest func(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) error
}

// ServeHTTP: RED stub (the test requires the method to exist).
func (h *wireHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// serveWithEmit: test seam. RED state: unused stub.
func (h *wireHandler) serveWithEmit(w http.ResponseWriter, r *http.Request, tx *ingest.TxContext, v *ladder.Verdict) {
}

// RequestIDFromContextOrGenerate returns the ctx request id, or a generated
// 128-bit id when absent. RED: returns "".
func RequestIDFromContextOrGenerate(ctx context.Context) string { return "" }

// trishulaIDValid reports whether id is a well-formed trishula request id
// (32 hex chars). RED: returns false.
func trishulaIDValid(id string) bool { return false }

// errNotWired is the wire sentinel (RED state marker).
type errNotWired struct{}

func (errNotWired) Error() string { return "otel: wire not wired" }
