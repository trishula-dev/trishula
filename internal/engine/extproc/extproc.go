// Package extproc serves the §10.4 variant-B wire contract: the
// envoy.service.ext_proc.v3.ExternalProcessor gRPC service (§19.1 ext_proc
// contract). Envoy-family data planes (TR-22) stream one transaction's
// stages down one Process stream: request headers, request body chunks
// (BUFFERED or STREAMED mode), trailers, and the response stages. The
// service answers every stage in place and never proxies anything: the
// gateway owns steering, the engine owns the verdict (the no-hop posture).
//
// Stage contract at this slice (§19.1 over the v0 consult surface,
// cmd/engine TR-08c posture):
//   - request headers: the stage evaluates. The wire header map folds the
//     §11.3 view seed scope (method, path, raw query); the header list and
//     the gateway-set dynamic metadata are never view material (§11.3
//     grows field-by-field, no speculative fields — the metadata context
//     is read only for policy lookup and never trusted as a payload fact).
//     The decisive vocabulary maps to ProcessingResponse: block = local
//     403 immediate response; ban = local 429 with Retry-After (the
//     window injects via Options.BanRetryAfter — the ban slice supplies
//     the real value; 0 omits the header); challenge continues (the
//     challenge flow rides a later slice, mirrored from the v0 consult);
//     allow and log continue.
//   - every other stage (request body/trailers, response headers/body/
//     trailers): consumed and continued. Chunks are never staged into the
//     view; request-body inspection and the response side are their own
//     slices (§8.2; R7b).
//
// Metadata contract (§19.1): every response writes the verdict, the
// matched-rule ids, the anomaly score and the ban flag under ONE metadata
// namespace, Namespace. The response mutations never name an EPP metadata
// key: x-gateway-destination-endpoint and its family stay untouched.
//
// Failure contract (§19.1): an evaluator error terminates the stream with
// an Internal status. The gateway's ext_proc fail-open/fail-close
// configuration owns the outcome. The service never swallows an error
// into a pass: a silent pass would forward unaudited traffic.
//
// Dependencies inject: the evaluator seam (Evaluator) separates the wire
// layer from the deciding engine (cmd/engine binds the loaded bundle;
// tests inject stubs), and Options carries the wire values. The package
// compiles kernel-free; the CI suite drives the full contract over the
// in-memory grpc test transport.
package extproc

import (
	"errors"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Evaluator is the injected evaluation seam: one §11.3 view request in,
// one ladder verdict out (the §19.1 Engine.EvaluateTx shape at the wire
// edge). cmd/engine binds the loaded bundle here; tests inject stubs.
type Evaluator interface {
	Evaluate(req cel.Request) (ladder.Verdict, error)
}

// Namespace is the single metadata namespace the engine writes verdicts
// into (§19.1: the WAF writes its own namespace, never EPP's).
const Namespace = "trishula.waf"

// Options carries the injected wire values. Nil selects the defaults; a
// zero BanRetryAfter omits the Retry-After header.
type Options struct {
	// BanRetryAfter is the Retry-After window on a 429 ban immediate
	// response. The value injects; the ban slice (TR-20) supplies the
	// real window when wired. 0 omits the header.
	BanRetryAfter time.Duration
}

// Server implements the ext_proc ExternalProcessor service (§10.4 variant
// B). One server serves many streams; one stream carries one HTTP
// transaction's stages.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	eval  Evaluator
	retry time.Duration
}

// New builds the service over eval. opts may be nil (defaults apply).
func New(eval Evaluator, opts *Options) *Server {
	if opts == nil {
		opts = &Options{}
	}
	return &Server{eval: eval, retry: opts.BanRetryAfter}
}

// Process serves one bidirectional stream: ProcessingRequest stages in,
// ProcessingResponse verdicts out. RED stub: the GREEN commit implements
// the §19.1 mapping (stage dispatch, the decisive vocabulary, the
// metadata namespace, the typed failure contract) and the contract tests
// pin it.
func (s *Server) Process(stream grpc.BidiStreamingServer[extprocv3.ProcessingRequest, extprocv3.ProcessingResponse]) error {
	return errPending
}

var errPending = errors.New("extproc: Process GREEN implementation pending (TR-22 §19.1 stage mapping)")
