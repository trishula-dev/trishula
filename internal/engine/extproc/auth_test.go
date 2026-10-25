// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package extproc

// TR-198 (issue #240) — the claims channel over the ext_proc wire: the
// gateway's verified identity metadata (ONE claims namespace, ONE
// identity_json field) stands in the view's request.auth vocabulary; every
// other metadata field and every regular header stays out of the view.
import (
	"io"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// headersReqWithMeta builds one headers-stage request with a metadata context.
func headersReqWithMeta(h map[string]string, claimsNS string, identityJSON string) *extprocv3.ProcessingRequest {
	req := headersReq(headMap(h))
	req.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
		claimsNS: {Fields: map[string]*structpb.Value{
			"identity_json": structpb.NewStringValue(identityJSON),
		}},
	}}
	return req
}

// TestClaimsChannelStandsInAuthVocabulary: the default claims namespace's
// identity_json carries the verified identity; the view's request.auth
// reads it (verified, subject, scopes) and nothing else moves.
func TestClaimsChannelStandsInAuthVocabulary(t *testing.T) {
	ev := &stubEval{}
	stream := newClient(t, ev, nil)
	identity := `{"verified":true,"claims":{"sub":"u1","iss":"https://issuer.example","aud":"api","scope":"read:orders","exp":1900000000}}`
	req := headersReqWithMeta(
		map[string]string{":method": "GET", ":path": "/orders/7"},
		DefaultAuthClaimsNamespace, identity)
	if err := stream.Send(req); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv: %v", err)
	}
	_ = io.Discard
	a := ev.saw.Auth
	if !a.Verified || a.Subject != "u1" || len(a.Scopes) != 1 || a.Scopes[0] != "read:orders" {
		t.Fatalf("view auth from the claims channel: got %+v, want verified u1 with read:orders", a)
	}
	if a.ExpiryEpoch != 1900000000 {
		t.Errorf("expiry epoch: got %d, want 1900000000", a.ExpiryEpoch)
	}
}

// TestClaimsChannelMissStaysUnverified: no namespace, no field, unusable
// bytes — the view reads the verified=false zero (the miss is clean).
func TestClaimsChannelMissStaysUnverified(t *testing.T) {
	cases := []struct {
		name  string
		ns    string
		value string
	}{
		{"no-metadata-context", DefaultAuthClaimsNamespace, ""},
		{"other-namespace-only", "envoy.filters.http.ext_proc", `{"verified":true}`},
		{"unusable-json", DefaultAuthClaimsNamespace, "{nope"},
	}
	for _, tc := range cases {
		ev := &stubEval{}
		stream := newClient(t, ev, nil)
		req := headersReq(headMap(map[string]string{":method": "GET", ":path": "/orders/7"}))
		if tc.value != "" {
			req = headersReqWithMeta(map[string]string{":method": "GET", ":path": "/orders/7"}, tc.ns, tc.value)
		}
		if err := stream.Send(req); err != nil {
			t.Fatalf("[%s] send: %v", tc.name, err)
		}
		if err := stream.CloseSend(); err != nil {
			t.Fatalf("[%s] close send: %v", tc.name, err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("[%s] recv: %v", tc.name, err)
		}
		a := ev.saw.Auth
		if a.Verified || a.Subject != "" {
			t.Errorf("[%s] view auth: got %+v, want the unverified zero", tc.name, a)
		}
	}
}

// TestClaimsChannelCustomNamespace: an Options naming another namespace
// moves the read; the default stays unread then (the payload-fact rule's
// scope rides the operator's setting).
func TestClaimsChannelCustomNamespace(t *testing.T) {
	ev := &stubEval{}
	stream := newClient(t, ev, &Options{AuthClaimsNamespace: "my.verifier"})
	identity := `{"verified":true,"claims":{"sub":"u9"}}`
	req := headersReqWithMeta(map[string]string{":method": "GET", ":path": "/x"}, "my.verifier", identity)
	if err := stream.Send(req); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv: %v", err)
	}
	if a := ev.saw.Auth; !a.Verified || a.Subject != "u9" {
		t.Fatalf("custom-namespace read: got %+v, want verified u9", a)
	}
}
