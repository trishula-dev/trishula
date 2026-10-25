// Package extproc serves the spec's ext_proc variant-B wire contract: the
// envoy.service.ext_proc.v3.ExternalProcessor gRPC service (the reference-implementation ext_proc
// contract). Envoy-family data planes (TR-22) stream one transaction's
// stages down one Process stream: request headers, request body chunks
// (BUFFERED or STREAMED mode), trailers, and the response stages. The
// service answers every stage in place and never proxies anything: the
// gateway owns steering, the engine owns the verdict (the no-hop posture).
//
// Stage contract at this slice (the reference-implementation sketch over the v0 consult surface,
// cmd/engine TR-08c posture):
//   - request headers: the stage evaluates. The wire header map folds the
//     the spec's view seed scope (method, path, raw query); the header list
//     is never view material (the spec's request view grows field-by-field,
//     no speculative fields). The gateway-set dynamic metadata context is
//     read only at ONE place: the claims channel (TR-198) — the gateway's
//     verified identity metadata the view's request.auth vocabulary
//     references; every other field stays unread and is never trusted as a
//     payload fact.
//     The decisive vocabulary maps to ProcessingResponse: block = local
//     403 immediate response; ban = local 429 with Retry-After (the
//     window injects via Options.BanRetryAfter — the ban slice supplies
//     the real value; 0 omits the header); challenge continues (the
//     challenge flow rides a later slice, mirrored from the v0 consult);
//     allow and log continue.
//   - every other stage (request body/trailers, response headers/body/
//     trailers): consumed and continued. Chunks are never staged into the
//     view; request-body inspection and the response side are their own
//     slices (the spec's component map; risk row R7b).
//
// Metadata contract (the reference-implementation sketch): every response writes the verdict, the
// matched-rule ids, the anomaly score and the ban flag under ONE metadata
// namespace, Namespace. The response mutations never name an EPP metadata
// key: x-gateway-destination-endpoint and its family stay untouched.
//
// Failure contract (the reference-implementation sketch): an evaluator error terminates the stream with
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Evaluator is the injected evaluation seam: one spec request view in,
// one ladder verdict out (the reference-implementation Engine.EvaluateTx shape at the wire
// edge). cmd/engine binds the loaded bundle here; tests inject stubs.
type Evaluator interface {
	Evaluate(req cel.Request) (ladder.Verdict, error)
}

// Namespace is the single metadata namespace the engine writes verdicts
// into (the reference-implementation sketch: the WAF writes its own namespace, never EPP's).
const Namespace = "trishula.waf"

// Options carries the injected wire values. Nil selects the defaults; a
// zero BanRetryAfter omits the Retry-After header.
type Options struct {
	// BanRetryAfter is the Retry-After window on a 429 ban immediate
	// response. The value injects; the ban slice (TR-20) supplies the
	// real window when wired. 0 omits the header.
	BanRetryAfter time.Duration
	// AuthClaimsNamespace is the gateway filter-metadata namespace the
	// claims channel lives under (TR-198): the ONE metadata context field
	// the view may read. The gateway's verifier (jwt_authn-family or the
	// operator's own hop) writes the verified identity metadata there with
	// the identity_json string field — the same channel unit
	// (cel.VerifiedIdentity) the ladder plumbing carries. Empty selects
	// the default. Every other namespace, and every other field, stays
	// unread (metadata is never a payload fact — the read-side rule).
	AuthClaimsNamespace string
}

// DefaultAuthClaimsNamespace is the claims channel's default namespace.
const DefaultAuthClaimsNamespace = "trishula.auth"

// Server implements the ext_proc ExternalProcessor service (the spec's ext_proc variant
// B). One server serves many streams; one stream carries one HTTP
// transaction's stages.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	eval  Evaluator
	retry time.Duration
	// claimsNS is the gateway claims channel's namespace (the wire read).
	claimsNS string
}

// New builds the service over eval. opts may be nil (defaults apply).
func New(eval Evaluator, opts *Options) *Server {
	if opts == nil {
		opts = &Options{}
	}
	ns := opts.AuthClaimsNamespace
	if ns == "" {
		ns = DefaultAuthClaimsNamespace
	}
	return &Server{eval: eval, retry: opts.BanRetryAfter, claimsNS: ns}
}

// Process serves one bidirectional stream: ProcessingRequest stages in,
// one ProcessingResponse out per stage, until the client half-closes.
// Messages stay independent (each stage answers alone, no cross-stage
// state); an evaluator error terminates the stream typed per the reference-implementation
// failure contract.
func (s *Server) Process(stream grpc.BidiStreamingServer[extprocv3.ProcessingRequest, extprocv3.ProcessingResponse]) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil // client half-close: the clean stream end
		}
		if err != nil {
			return err // transport failure: the runtime owns the typed status
		}
		resp, err := s.respond(req)
		if err != nil {
			// The reference-implementation sketch: the stream fails typed. The gateway's
			// fail-open/fail-close configuration owns the outcome; the
			// service never swallows the error into a pass.
			return status.Error(codes.Internal, "trishula: "+err.Error())
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// respond maps one received stage to its reference-implementation response.
func (s *Server) respond(req *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	switch r := req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return s.headersResponse(r.RequestHeaders, req.GetMetadataContext())
	default:
		return stageContinue(req), nil
	}
}

// headersResponse evaluates the request-headers stage over the seed view
// and maps the ladder vocabulary to the wire (the reference-implementation sketch): block = local 403,
// ban = local 429 with the injected Retry-After window, everything else
// continues with the verdict record in the namespace metadata.
func (s *Server) headersResponse(h *extprocv3.HttpHeaders, mc *corev3.Metadata) (*extprocv3.ProcessingResponse, error) {
	v, err := s.eval.Evaluate(s.viewOf(h, mc))
	if err != nil {
		return nil, fmt.Errorf("evaluator: %w", err)
	}
	meta, err := metadataOf(v)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	switch v.Action {
	case ladder.ActionBlock:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: blockResponse(v),
			},
			DynamicMetadata: meta,
		}, nil
	case ladder.ActionBan:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: s.banResponse(v),
			},
			DynamicMetadata: meta,
		}, nil
	default:
		// allow, log and challenge continue: the challenge flow rides a
		// later slice (the v0 consult mirror); a log is no enforcement;
		// an empty action string stays a pass at this slice.
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extprocv3.HeadersResponse{
					Response: continueCommon(),
				},
			},
			DynamicMetadata: meta,
		}, nil
	}
}

// blockResponse builds the local 403 immediate response; the matched
// rule names the reply body and details when provenance exists (the reference-implementation sketch:
// matched-rule ids surface on the local reply, not just in metadata).
func blockResponse(v ladder.Verdict) *extprocv3.ImmediateResponse {
	imm := &extprocv3.ImmediateResponse{
		Status:  &envoytype.HttpStatus{Code: envoytype.StatusCode_Forbidden},
		Details: "trishula: block",
	}
	if rule := firstRule(v); rule != "" {
		imm.Body = []byte("blocked by " + rule)
		imm.Details = "trishula: block (" + rule + ")"
	}
	return imm
}

// banResponse builds the local 429 immediate response. The injected
// window stamps Retry-After; 0 omits the header (Options carries the
// contract; the ban slice supplies the real value when wired).
func (s *Server) banResponse(v ladder.Verdict) *extprocv3.ImmediateResponse {
	imm := &extprocv3.ImmediateResponse{
		Status:  &envoytype.HttpStatus{Code: envoytype.StatusCode_TooManyRequests},
		Details: "trishula: ban",
	}
	if rule := firstRule(v); rule != "" {
		imm.Body = []byte("banned by " + rule)
		imm.Details = "trishula: ban (" + rule + ")"
	}
	if s.retry > 0 {
		imm.Headers = &extprocv3.HeaderMutation{
			SetHeaders: []*corev3.HeaderValueOption{{
				Header: &corev3.HeaderValue{Key: "retry-after", Value: strconv.Itoa(int(s.retry / time.Second))},
			}},
		}
	}
	return imm
}

// stageContinue answers every non-evaluated stage: request body and
// trailers plus the response side consume and continue (the package
// boundary above). The response case mirrors the stage's own kind.
func stageContinue(req *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	switch req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestBody:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{Response: continueCommon()},
			},
		}
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extprocv3.HeadersResponse{Response: continueCommon()},
			},
		}
	case *extprocv3.ProcessingRequest_ResponseBody:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ResponseBody{
				ResponseBody: &extprocv3.BodyResponse{Response: continueCommon()},
			},
		}
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestTrailers{
				RequestTrailers: &extprocv3.TrailersResponse{},
			},
		}
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &extprocv3.TrailersResponse{},
			},
		}
	default:
		// An empty stage message (flow-control-only shape): keep the
		// stream alive with a bare response.
		return &extprocv3.ProcessingResponse{}
	}
}

func continueCommon() *extprocv3.CommonResponse {
	return &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}
}

// viewOf folds the wire header map into the spec's request-view seed scope:
// method from the method pseudo header, path and query from the path
// pseudo header, split at the first question mark. Raw-value encoding
// reads over the string form (the data plane encodes wire values in
// raw_value). The regular header fields stay out at this slice (the spec's
// view grows field-by-field, no speculative fields).
//
// The ONE metadata context read is the claims channel (TR-198): the
// claims namespace's identity_json string field carries the gateway's
// verified identity metadata (the same JSON unit the ladder plumbing
// attaches) and stands in the view's request.auth vocabulary. Verified
// identity metadata is not a payload fact: the gateway's verifier produced
// it; the engine references it and stores nothing. Every other namespace
// and every other field stays unread; an unusable channel reads the miss
// (verified=false), never a fabricated identity.
func (s *Server) viewOf(h *extprocv3.HttpHeaders, mc *corev3.Metadata) (view cel.Request) {
	for _, hv := range h.GetHeaders().GetHeaders() {
		name, value := hv.GetKey(), hv.GetValue()
		if raw := hv.GetRawValue(); len(raw) > 0 {
			value = string(raw)
		}
		switch name {
		case ":method":
			view.Method = value
		case ":path":
			view.Path, view.Query, _ = strings.Cut(value, "?")
		}
	}
	if vi := s.claimsChannel(mc); vi != nil {
		view.Auth = vi.AuthView().Sanitised()
	} else {
		view.Auth = cel.Auth{}.Sanitised()
	}
	return view
}

// claimsChannel reads the gateway's verified identity metadata out of the
// headers stage's metadata context (nil = the miss: no claims namespace,
// no identity field, unusable bytes). The read touches ONLY the claims
// namespace's identity_json field and only decodes the channel unit —
// the identity header list and every other metadata field never join the
// view (the payload-fact rule).
func (s *Server) claimsChannel(mc *corev3.Metadata) *cel.VerifiedIdentity {
	structs := mc.GetFilterMetadata()
	filter, ok := structs[s.claimsNS]
	if !ok || filter.GetFields()["identity_json"] == nil {
		return nil
	}
	var vi cel.VerifiedIdentity
	if err := json.Unmarshal([]byte(filter.GetFields()["identity_json"].GetStringValue()), &vi); err != nil {
		return nil
	}
	return &vi
}

// metadataOf builds one response's dynamic metadata write: the verdict,
// the matched-rule ids, the anomaly score and the ban flag, all under the
// engine's one namespace (the reference-implementation sketch). The namespace carries those four
// fields only; a write never touches another namespace, so EPP's
// x-gateway-destination-endpoint keys stay out of reach.
func metadataOf(v ladder.Verdict) (*structpb.Struct, error) {
	rules := make([]any, 0, len(v.Rules))
	for _, r := range v.Rules {
		rules = append(rules, string(r))
	}
	return structpb.NewStruct(map[string]any{
		Namespace: map[string]any{
			"verdict": string(v.Action),
			"rules":   rules,
			"anomaly": v.Score,
			"ban":     v.Action == ladder.ActionBan,
		},
	})
}

// firstRule reads the first matched-rule id of a verdict (an empty string
// when the verdict carries no provenance).
func firstRule(v ladder.Verdict) string {
	if len(v.Rules) == 0 {
		return ""
	}
	return string(v.Rules[0])
}
