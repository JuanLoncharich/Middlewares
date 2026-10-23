package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const journalPolicy = `
redaction_token: "[REDACTED]"
detectors:
  - name: email
    pattern: '[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}'
`

func journalGateway(t *testing.T, seen *http.Header, seenBody *string) *gateway {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		*seenBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jsonAnswer)
	}))
	t.Cleanup(up.Close)
	base, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte(journalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	return &gateway{policyPath: policy, upstreamBase: base, client: up.Client(), inflight: newInflightLimiter(4), journal: &journal{}}
}

func chat(g *gateway, client string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"lfm","messages":[{"role":"user","content":"write to ana@example.com"}]}`))
	if client != "" {
		req.Header.Set(clientHeader, client)
	}
	rr := httptest.NewRecorder()
	g.serve(rr, req)
	return rr
}

func readJournal(t *testing.T, g *gateway, query string) []journalEntry {
	t.Helper()
	rr := httptest.NewRecorder()
	g.journal.inspectHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/requests?"+query, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /requests?%s = %d %s", query, rr.Code, rr.Body.String())
	}
	var out struct{ Entries []journalEntry }
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Entries
}

func TestJournalRecordsMetadataForNamedClientsOnly(t *testing.T) {
	var seen http.Header
	var body string
	g := journalGateway(t, &seen, &body)

	if rr := chat(g, ""); rr.Code != http.StatusOK {
		t.Fatalf("anonymous request: %d", rr.Code)
	}
	if rr := chat(g, "ui-chat"); rr.Code != http.StatusOK {
		t.Fatalf("ui-chat request: %d", rr.Code)
	}
	if seen.Get(clientHeader) != "" {
		t.Fatal("the client name leaked to the upstream provider")
	}
	if strings.Contains(body, "ana@example.com") {
		t.Fatal("the email reached the upstream unredacted")
	}

	entries := readJournal(t, g, "client=ui-chat")
	if len(entries) != 1 {
		t.Fatalf("want only the named request journaled, got %d", len(entries))
	}
	e := entries[0]
	if e.Redactions["email"] != 1 || e.Status != 200 || e.ServedBy != "primary" || e.Model != "lfm" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	if e.ResponseBytes != int64(len(jsonAnswer)) || e.RequestBytes == 0 {
		t.Fatalf("sizes not recorded: %+v", e)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "example.com") || strings.Contains(string(raw), "write to") {
		t.Fatalf("journal holds content: %s", raw)
	}

	if got := readJournal(t, g, "client=ui-chat&after="+itoa(e.ID)); len(got) != 0 {
		t.Fatalf("after=%d still returns %d entries", e.ID, len(got))
	}
}

func TestJournalRejectsMalformedClients(t *testing.T) {
	g := &gateway{journal: &journal{}}
	rr := httptest.NewRecorder()
	g.journal.inspectHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/requests", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("listing without a client = %d, want 400", rr.Code)
	}
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set(clientHeader, "UI Chat; drop")
	if clientOf(req) != "" {
		t.Fatal("malformed client name accepted")
	}
}

func TestJournalKeepsTheLatestEntries(t *testing.T) {
	j := &journal{}
	for i := 0; i < journalSize+5; i++ {
		j.add(journalEntry{Client: "ui-chat"})
	}
	got := j.since("ui-chat", 0)
	if len(got) != journalSize || got[0].ID != 6 {
		t.Fatalf("ring kept %d entries starting at %d", len(got), got[0].ID)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
