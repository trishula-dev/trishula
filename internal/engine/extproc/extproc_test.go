package extproc

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// stubEval records the view it saw and returns the wired answers.
// Every test feeds its own verdict or error (deps injected).
type stubEval struct {
	v   ladder.Verdict
	err error
	saw cel.Request
}

func (e *stubEval) Evaluate(req cel.Request) (ladder.Verdict, error) {
	e.saw = req
	return e.v, e.err
}

// newClient builds the in-process harness: the server registers over a
// bufconn listener and the client connects in memory. The transport IS
// the surface under test here, so a real in-memory gRPC stack carries the
// wire contract (kernel-free, no sockets, CI-runnable).
func newClient(t *testing.T, eval Evaluator, opts *Options) extprocv3.ExternalProcessor_ProcessClient {
	t.Helper()
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv, New(eval, opts))
	lis := bufconn.Listen(64 * 1024)
	go srv.Serve(lis)
	conn, err := grpc.NewClient("passthrough:///trishula-extproc-test",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(context.Background())
	if err != nil {
		t.Fatalf("open Process stream: %v", err)
	}
	return stream
}

// headMap builds one wire header map. Names list in sorted order for a
// deterministic wire shape.
func headMap(kvs map[string]string) *corev3.HeaderMap {
	m := &corev3.HeaderMap{}
	names := make([]string, 0, len(kvs))
	for k := range kvs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		m.Headers = append(m.Headers, &corev3.HeaderValue{Key: k, Value: kvs[k]})
	}
	return m
}

// headersReq wraps a header map into the request-headers stage message.
func headersReq(head *corev3.HeaderMap) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{Headers: head},
		},
	}
}

func bodyReq(n int) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: make([]byte, n)},
		},
	}
}

// TestProcessStageMapping is the verdict-mapping home table: every stage
// the service receives maps to its §19.1 response, and the decisive
// vocabulary maps to immediate responses (block 403, ban 429 with the
// injected Retry-After window), while non-decisive verdicts and the
// non-evaluated stages continue.
func TestProcessStageMapping(t *testing.T) {
	tests := []struct {
		name  string
		opts  *Options
		eval  stubEval
		req   *extprocv3.ProcessingRequest
		check func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse)
	}{
		{
			name: "allow continues and projects the seed view",
			eval: stubEval{v: ladder.Verdict{Action: ladder.ActionAllow, Rules: []ladder.RuleID{"cel:seed-rate-shape"}, Phase: ladder.PhaseRequestHeaders}},
			req:  headersReq(headMap(map[string]string{":method": "POST", ":path": "/v1/chat?trace=on", ":authority": "api.example.com"})),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				switch resp.GetResponse().(type) {
				case *extprocv3.ProcessingResponse_RequestHeaders:
				default:
					t.Errorf("response oneof: got %T, want RequestHeaders", resp.GetResponse())
				}
				if imm := resp.GetImmediateResponse(); imm != nil {
					t.Errorf("allow verdict: got an immediate response %v, want none", imm)
				}
				common := resp.GetRequestHeaders().GetResponse()
				if common.GetStatus() != extprocv3.CommonResponse_CONTINUE {
					t.Errorf("continue status: got %v, want CONTINUE", common.GetStatus())
				}
				want := cel.Request{Method: "POST", Path: "/v1/chat", Query: "trace=on"}
				if !reflect.DeepEqual(ev.saw, want) {
					t.Errorf("seed view: got %+v, want %+v", ev.saw, want)
				}
			},
		},
		{
			name: "block answers local 403",
			eval: stubEval{v: ladder.Verdict{Action: ladder.ActionBlock, Rules: []ladder.RuleID{"cel:seed-rate-shape"}, Score: 7, Phase: ladder.PhaseRequestHeaders}},
			req:  headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"})),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				imm := resp.GetImmediateResponse()
				if imm == nil {
					t.Fatalf("block verdict: got no immediate response, want local 403 (response oneof %T)", resp.GetResponse())
				}
				if code := imm.GetStatus().GetCode(); int(code) != 403 {
					t.Errorf("block status code: got %d, want 403", int(code))
				}
				if got, want := string(imm.GetBody()), "blocked by cel:seed-rate-shape"; got != want {
					t.Errorf("block body: got %q, want %q", got, want)
				}
			},
		},
		{
			name: "ban answers 429 with the injected Retry-After window",
			opts: &Options{BanRetryAfter: time.Minute},
			eval: stubEval{v: ladder.Verdict{Action: ladder.ActionBan, Rules: []ladder.RuleID{"rateban:swb"}, Phase: ladder.PhaseRequestHeaders}},
			req:  headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"})),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				imm := resp.GetImmediateResponse()
				if imm == nil {
					t.Fatalf("ban verdict: got no immediate response, want local 429")
				}
				if code := imm.GetStatus().GetCode(); int(code) != 429 {
					t.Errorf("ban status code: got %d, want 429", int(code))
				}
				if got, want := retryAfterOf(imm), "60"; got != want {
					t.Errorf("retry-after: got %q, want %q", got, want)
				}
			},
		},
		{
			name: "ban without a window omits the Retry-After header",
			eval: stubEval{v: ladder.Verdict{Action: ladder.ActionBan, Rules: []ladder.RuleID{"rateban:swb"}, Phase: ladder.PhaseRequestHeaders}},
			req:  headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"})),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				imm := resp.GetImmediateResponse()
				if imm == nil {
					t.Fatalf("ban verdict: got no immediate response, want local 429")
				}
				if got := retryAfterOf(imm); got != "" {
					t.Errorf("retry-after at zero window: got %q, want the header omitted", got)
				}
			},
		},
		{
			name: "challenge continues (the flow rides a later slice, v0 consult mirror)",
			eval: stubEval{v: ladder.Verdict{Action: ladder.ActionChallenge, Rules: []ladder.RuleID{"cel:seed-challenge"}, Phase: ladder.PhaseRequestHeaders}},
			req:  headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"})),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				if imm := resp.GetImmediateResponse(); imm != nil {
					t.Errorf("challenge: got an immediate response, want continue (v0 consult mirror)")
				}
				common := resp.GetRequestHeaders().GetResponse()
				if common.GetStatus() != extprocv3.CommonResponse_CONTINUE {
					t.Errorf("challenge continue status: got %v, want CONTINUE", common.GetStatus())
				}
			},
		},
		{
			name: "log continues and carries the matched rule in metadata",
			eval: stubEval{v: ladder.Verdict{Action: ladder.ActionLog, Rules: []ladder.RuleID{"crs:942100"}, Phase: ladder.PhaseRequestHeaders}},
			req:  headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"})),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				if imm := resp.GetImmediateResponse(); imm != nil {
					t.Errorf("log verdict: got an immediate response, want continue")
				}
				if common := resp.GetRequestHeaders().GetResponse(); common.GetStatus() != extprocv3.CommonResponse_CONTINUE {
					t.Errorf("log continue status: got %v, want CONTINUE", common.GetStatus())
				}
				inner := namespaceOf(t, resp)
				if got := inner.GetFields()["rules"].GetListValue().GetValues(); len(got) != 1 || got[0].GetStringValue() != "crs:942100" {
					t.Errorf("matched-rule ids in metadata: got %v, want [crs:942100]", got)
				}
			},
		},
		{
			name: "request body chunk continues and never reaches the view",
			req:  bodyReq(64),
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				switch resp.GetResponse().(type) {
				case *extprocv3.ProcessingResponse_RequestBody:
				default:
					t.Errorf("body stage response: got %T, want RequestBody", resp.GetResponse())
				}
				if !reflect.DeepEqual(ev.saw, cel.Request{}) {
					t.Errorf("body chunk reached the view: got %+v, want the zero view (chunks are never staged at this slice)", ev.saw)
				}
			},
		},
		{
			name: "response headers stage continues",
			req: &extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &extprocv3.HttpHeaders{},
				},
			},
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				switch resp.GetResponse().(type) {
				case *extprocv3.ProcessingResponse_ResponseHeaders:
				default:
					t.Errorf("response-headers stage: got %T, want ResponseHeaders", resp.GetResponse())
				}
				if !reflect.DeepEqual(ev.saw, cel.Request{}) {
					t.Errorf("response stage evaluated: got %+v, want no view (the response side is a later slice)", ev.saw)
				}
			},
		},
		{
			name: "request trailers continue",
			req: &extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestTrailers{
					RequestTrailers: &extprocv3.HttpTrailers{},
				},
			},
			check: func(t *testing.T, ev *stubEval, resp *extprocv3.ProcessingResponse) {
				switch resp.GetResponse().(type) {
				case *extprocv3.ProcessingResponse_RequestTrailers:
				default:
					t.Errorf("trailers stage: got %T, want RequestTrailers", resp.GetResponse())
				}
			},
		},
	}
	for i := range tests {
		tc := tests[i]
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.eval
			stream := newClient(t, &ev, tc.opts)
			if err := stream.Send(tc.req); err != nil {
				t.Fatalf("send stage: %v", err)
			}
			if err := stream.CloseSend(); err != nil {
				t.Fatalf("close send: %v", err)
			}
			resp, err := stream.Recv()
			if err != nil {
				t.Fatalf("recv response: %v", err)
			}
			tc.check(t, &ev, resp)
		})
	}
}

// TestMetadataNamespaceContract pins the §19.1 metadata discipline over
// one stream carrying three stages: exactly one top-level namespace key
// per response, the verdict/rules/anomaly/ban shape inside, and no header
// mutation ever naming an EPP metadata key.
func TestMetadataNamespaceContract(t *testing.T) {
	ev := &stubEval{}
	stream := newClient(t, ev, &Options{BanRetryAfter: time.Minute})
	stages := []struct {
		name string
		req  *extprocv3.ProcessingRequest
	}{
		{"headers", headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"}))},
		{"body", bodyReq(16)},
		{"trailers", &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestTrailers{
				RequestTrailers: &extprocv3.HttpTrailers{},
			},
		}},
	}
	for _, st := range stages {
		if err := stream.Send(st.req); err != nil {
			t.Fatalf("send %s stage: %v", st.name, err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv %s stage response: %v", st.name, err)
		}
		if st.name == "headers" {
			// The evaluated stage writes the verdict record: exactly one
			// top-level namespace key, the verdict/rules/anomaly/ban
			// shape inside.
			meta := resp.GetDynamicMetadata()
			if meta == nil {
				t.Fatalf("headers stage: got no dynamic metadata, want the %s namespace write", Namespace)
			}
			if n := len(meta.GetFields()); n != 1 {
				t.Errorf("headers stage: top-level metadata namespaces: got %d, want exactly 1 (%s)", n, Namespace)
			}
			if _, ok := meta.GetFields()[Namespace]; !ok {
				t.Errorf("headers stage: metadata carries no %s namespace key: %v", Namespace, meta.GetFields())
			}
			if inner := namespaceOf(t, resp); inner == nil {
				t.Errorf("headers stage: %s namespace carries no struct value", Namespace)
			} else {
				want := map[string]bool{"verdict": true, "rules": true, "anomaly": true, "ban": true}
				for key := range inner.GetFields() {
					if !want[key] {
						t.Errorf("headers stage: unexpected %s field %q (the namespace carries verdict, rules, anomaly, ban only)", Namespace, key)
					}
				}
			}
		} else if meta := resp.GetDynamicMetadata(); meta != nil && len(meta.GetFields()) > 0 {
			t.Errorf("%s stage wrote metadata though no stage evaluated it: %v", st.name, meta.GetFields())
		}
		key := eppMutationKey(resp)
		if key != "" {
			t.Errorf("%s stage: response mutation names EPP metadata key %q (the WAF never mutates that family)", st.name, key)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("after CloseSend: got %v, want io.EOF", err)
	}
}

// namespaceOf reads the engine's metadata struct out of one response.
func namespaceOf(t *testing.T, resp *extprocv3.ProcessingResponse) *structpb.Struct {
	t.Helper()
	return resp.GetDynamicMetadata().GetFields()[Namespace].GetStructValue()
}

// retryAfterOf reads the Retry-After value out of one immediate response
// (an empty string when absent).
func retryAfterOf(imm *extprocv3.ImmediateResponse) string {
	for _, set := range imm.GetHeaders().GetSetHeaders() {
		if strings.EqualFold(set.GetHeader().GetKey(), "retry-after") {
			return set.GetHeader().GetValue()
		}
	}
	return ""
}

// eppMutationKey returns the first header-mutation key the response
// carries under the EPP metadata family (an empty string when none).
func eppMutationKey(resp *extprocv3.ProcessingResponse) string {
	for _, key := range mutationKeys(resp.GetImmediateResponse()) {
		if strings.HasPrefix(key, "x-gateway-destination-endpoint") {
			return key
		}
	}
	return ""
}

// mutationKeys lists every header key one immediate response sets or
// removes.
func mutationKeys(imm *extprocv3.ImmediateResponse) []string {
	if imm == nil {
		return nil
	}
	var keys []string
	for _, set := range imm.GetHeaders().GetSetHeaders() {
		keys = append(keys, set.GetHeader().GetKey())
	}
	return append(keys, imm.GetHeaders().GetRemoveHeaders()...)
}

// TestMetadataContextNeverPayloadFact pins the read-side rule: the
// gateway-set dynamic metadata is never request material, so the view the
// evaluator sees carries the wire headers only.
func TestMetadataContextNeverPayloadFact(t *testing.T) {
	ev := &stubEval{}
	stream := newClient(t, ev, nil)
	req := headersReq(headMap(map[string]string{":method": "POST", ":path": "/v1/chat", ":authority": "api.example.com"}))
	req.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
		"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"authorized": structpb.NewBoolValue(true),
			"path":       structpb.NewStringValue("/admin"),
		}},
	}}
	if err := stream.Send(req); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv response: %v", err)
	}
	want := cel.Request{Method: "POST", Path: "/v1/chat"}
	if !reflect.DeepEqual(ev.saw, want) {
		t.Errorf("view with a shaped metadata context: got %+v, want %+v (metadata is never a payload fact)", ev.saw, want)
	}
}

// TestEvaluatorErrorStream pins the failure contract: an evaluator error
// terminates the stream with an Internal status and never ships a pass —
// the gateway's fail-open/fail-close configuration owns the outcome.
func TestEvaluatorErrorStream(t *testing.T) {
	ev := &stubEval{err: errors.New("boom: bundle lost")}
	stream := newClient(t, ev, nil)
	if err := stream.Send(headersReq(headMap(map[string]string{":method": "GET", ":path": "/v1/chat"}))); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	_, err := stream.Recv()
	if err == nil {
		t.Fatalf("evaluator error: got a response, want a stream error")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Errorf("failure status: got %v, want %v", st.Code(), codes.Internal)
	}
	if !strings.Contains(st.Message(), "boom: bundle lost") {
		t.Errorf("failure detail: got %q, want the evaluator error text", st.Message())
	}
}
