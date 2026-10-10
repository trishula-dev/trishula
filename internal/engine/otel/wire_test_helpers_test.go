// wire_test.go — middleware test helpers (in-package; the net/http adapter
// tests reuse the correlation_test fixtures via kvGet/newTestPipeline).
package otel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newRecorder builds a fresh httptest recorder per call.
func newRecorder() *httptest.ResponseRecorder {
	return &httptest.ResponseRecorder{}
}

// newRequest builds a plain request (no headers unless the test adds them).
func newRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if req == nil {
		t.Fatalf("httptest.NewRequest(%q,%q) = nil", method, path)
	}
	return req
}
