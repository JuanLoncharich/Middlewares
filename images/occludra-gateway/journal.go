package main

// Request journal: what the gateway did with each inference request of a
// client that names itself with X-Occludra-Client (the UI chat sends
// "ui-chat"). It keeps metadata only — model, redaction counts per detector,
// block reason, upstream status, timing and sizes — never prompt or answer
// content, the same rule as the gateway log. Evaluation traffic sends no
// client name and is never journaled.
//
// The journal is served on its own listener (OCCLUDRA_INSPECT_LISTEN, off by
// default) so a NetworkPolicy can let the UI read it without letting the UI
// reach the inference port.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	clientHeader   = "X-Occludra-Client"
	upstreamHeader = "X-Occludra-Upstream"
	journalSize    = 100
)

var clientName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type journalEntry struct {
	ID            int64          `json:"id"`
	At            time.Time      `json:"at"`
	Client        string         `json:"client"`
	Model         string         `json:"model,omitempty"`
	Redactions    map[string]int `json:"redactions"`
	BlockedBy     string         `json:"blockedBy,omitempty"`
	Status        int            `json:"status"`
	Upstream      string         `json:"upstream,omitempty"`
	ServedBy      string         `json:"servedBy,omitempty"`
	DurationMs    int64          `json:"durationMs"`
	RequestBytes  int            `json:"requestBytes"`
	ResponseBytes int64          `json:"responseBytes"`
}

type journal struct {
	mu      sync.Mutex
	next    int64
	entries []journalEntry
}

func (j *journal) add(e journalEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.next++
	e.ID = j.next
	j.entries = append(j.entries, e)
	if len(j.entries) > journalSize {
		j.entries = j.entries[len(j.entries)-journalSize:]
	}
}

// since returns the client's entries with an ID greater than after, oldest first.
func (j *journal) since(client string, after int64) []journalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := []journalEntry{}
	for _, e := range j.entries {
		if e.Client == client && e.ID > after {
			out = append(out, e)
		}
	}
	return out
}

// clientOf returns the request's self-declared client name, or "" when it
// is missing or malformed (then nothing is journaled).
func clientOf(r *http.Request) string {
	name := r.Header.Get(clientHeader)
	if !clientName.MatchString(name) {
		return ""
	}
	return name
}

// countingWriter records the status and body size the client actually got.
type countingWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (c *countingWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(p)
	c.bytes += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// inspectHandler serves GET /requests?client=<name>&after=<id>.
func (j *journal) inspectHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		client := r.URL.Query().Get("client")
		if !clientName.MatchString(client) {
			http.Error(w, "client is required", http.StatusBadRequest)
			return
		}
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": j.since(client, after)})
	})
	return mux
}
