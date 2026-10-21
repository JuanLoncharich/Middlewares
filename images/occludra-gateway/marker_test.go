package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// proxyOnce sends one chat completion through the gateway to a fake upstream
// that answers body with contentType.
func proxyOnce(t *testing.T, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	base, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{upstreamBase: base, client: up.Client()}
	rr := httptest.NewRecorder()
	g.proxy(rr, httptest.NewRequest("POST", "/v1/chat/completions", nil), []byte(`{}`), 2)
	return rr
}

const jsonAnswer = `{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"clean\"}"}}]}`
const sseAnswer = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"

func TestAnswersPassUnmodifiedByDefault(t *testing.T) {
	t.Setenv("OCCLUDRA_RESPONSE_MARKER", "")
	for _, c := range []struct{ ct, body string }{{"application/json", jsonAnswer}, {"text/event-stream", sseAnswer}} {
		rr := proxyOnce(t, c.ct, c.body)
		if rr.Body.String() != c.body {
			t.Fatalf("%s answer changed:\n got %q\nwant %q", c.ct, rr.Body.String(), c.body)
		}
		if rr.Header().Get("X-Occludra-Proxy") != "true" {
			t.Fatalf("%s answer lacks X-Occludra-Proxy", c.ct)
		}
	}
}

func TestMarkerIsOptIn(t *testing.T) {
	t.Setenv("OCCLUDRA_RESPONSE_MARKER", "1")
	if rr := proxyOnce(t, "application/json", jsonAnswer); !strings.Contains(rr.Body.String(), `clean\"} (proxy)"`) {
		t.Fatalf("JSON answer without marker: %s", rr.Body.String())
	}
	if rr := proxyOnce(t, "text/event-stream", sseAnswer); !strings.Contains(rr.Body.String(), "(proxy)") {
		t.Fatalf("SSE answer without marker: %s", rr.Body.String())
	}
	for _, off := range []string{"0", "false", "off", "no"} {
		t.Setenv("OCCLUDRA_RESPONSE_MARKER", off)
		if responseMarkerEnabled() {
			t.Fatalf("OCCLUDRA_RESPONSE_MARKER=%s enables the marker", off)
		}
	}
}
