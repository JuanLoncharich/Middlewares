package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestObservedWriterPreservesStreaming(t *testing.T) {
	flushed := false
	h := observeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		flushed = true
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if !flushed || !rr.Flushed || !strings.Contains(rr.Body.String(), "[DONE]") {
		t.Fatal("SSE stream or flushing lost")
	}
	if routeName("/arbitrary-client-controlled-path") != "other" {
		t.Fatal("unbounded metric route")
	}
}

func TestFinalUpstreamErrorIsPreservedAndTraceHeadersArePrivate(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"traceparent", "tracestate", "baggage", "x-mcp-run"} {
			if r.Header.Get(header) != "" {
				t.Errorf("internal header sent upstream: %s", header)
			}
		}
		w.WriteHeader(429)
		io.WriteString(w, `{"error":"rate limited"}`)
	}))
	defer up.Close()
	base, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{upstreamBase: base, client: up.Client()}
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	req.Header.Set("x-mcp-run", "private-run")
	rr := httptest.NewRecorder()
	g.proxy(rr, req, []byte(`{}`), 2)
	if rr.Code != 429 || !strings.Contains(rr.Body.String(), "rate limited") {
		t.Fatalf("lost upstream failure: %d %s", rr.Code, rr.Body.String())
	}
}
