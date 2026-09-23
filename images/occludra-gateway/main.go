// Occludra reference gateway: an OpenAI-compatible LLM egress proxy with
// regex-based PII/secret redaction.
//
// Sits between the evaluation runner's OpenCode providers and the upstream
// provider. Every /v1/chat/completions body is walked recursively and every
// string value is matched against the configured detectors; matches are
// replaced with the redaction token (or the request is rejected for
// action=block detectors). Model names are checked against an allowlist.
// Responses (including SSE streams) are piped back unmodified.
//
// Configuration:
//
//	OCCLUDRA_LISTEN             listen address (default 0.0.0.0:8080)
//	OCCLUDRA_POLICY_FILE        policy YAML path (default /conf/policy.yaml)
//	OCCLUDRA_UPSTREAM_BASE_URL  upstream OpenAI-compatible base URL
//	                            (default https://opencode.ai/zen/v1)
//	OCCLUDRA_UPSTREAM_API_KEY   upstream key (falls back to OPENCODE_API_KEY,
//	                            then ANTHROPIC_API_KEY)
//
// Logging counts and classifies redactions only — prompt content is never
// written to the gateway log.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

func envInt(key string, def int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return v
		}
	}
	return def
}

// Policy mirrors manifests/occludra-deployment.yaml ConfigMap occludra-policy.
type Policy struct {
	Version        int            `yaml:"version"`
	DefaultAction  string         `yaml:"default_action"`
	RedactionToken string         `yaml:"redaction_token"`
	Detectors      []Detector     `yaml:"detectors"`
	Models         ModelsPolicy   `yaml:"models"`
	Logging        LoggingPolicy  `yaml:"logging"`
	Upstream       UpstreamPolicy `yaml:"upstream"`
}

type Detector struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
	re      *regexp.Regexp
}

type ModelsPolicy struct {
	Allow []string `yaml:"allow"`
	re    []*regexp.Regexp
}

type LoggingPolicy struct {
	LogPrompts    bool `yaml:"log_prompts"`
	LogRedactions bool `yaml:"log_redactions"`
}

type UpstreamPolicy struct {
	BaseURL string `yaml:"base_url"`
}

const maxBodyBytes = 32 << 20

// inflightLimiter is a plain counting semaphore: at saturation the gateway
// answers 503 + Retry-After instead of accepting unbounded work (each scrub
// holds a full request body plus a potentially minutes-long SSE stream, so
// memory is the resource that runs out first). Clients retry with backoff.
type inflightLimiter struct {
	mu    sync.Mutex
	used  int
	limit int
}

func newInflightLimiter(limit int) *inflightLimiter {
	if limit <= 0 {
		limit = 1
	}
	return &inflightLimiter{limit: limit}
}

// acquire reserves a slot, waiting up to timeout for one to free; it reports
// saturation (false) if none frees in time. The mutex is only held for the
// check/increment, never across the wait.
func (l *inflightLimiter) acquire(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		l.mu.Lock()
		if l.used < l.limit {
			l.used++
			l.mu.Unlock()
			return true
		}
		l.mu.Unlock()
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (l *inflightLimiter) release() {
	l.mu.Lock()
	l.used--
	l.mu.Unlock()
}

type gateway struct {
	policyPath   string
	upstreamBase *url.URL
	upstreamKey  string
	// Optional secondary LLM provider: on primary transport failure,
	// 5xx or 429 the request is retried here before the first byte is
	// streamed to the client. Removes the single-upstream SPOF.
	fallbackBase *url.URL
	fallbackKey  string
	client       *http.Client
	inflight     *inflightLimiter
}

// currentPolicy loads the policy file on demand. ConfigMap volume updates
// propagate to the mounted file, so every request sees the freshest policy
// without a pod restart; on a transient read/parse error the previous
// in-memory copy is kept (callers pass it back in).
func (g *gateway) currentPolicy(previous *Policy) *Policy {
	p, err := loadPolicy(g.policyPath)
	if err != nil {
		if previous != nil {
			log.Printf("policy reload failed, keeping previous version: %v", err)
			return previous
		}
		log.Fatalf("loading policy: %v", err)
	}
	return p
}

type requestStats struct {
	model          string
	redactions     map[string]int
	blockedBy      string
	upstreamStatus int
}

func main() {
	policyPath := envOr("OCCLUDRA_POLICY_FILE", "/conf/policy.yaml")
	policy, err := loadPolicy(policyPath)
	if err != nil {
		log.Fatalf("loading policy %s: %v", policyPath, err)
	}

	// Precedence: env > policy > built-in default (OpenCode Zen).
	upstreamRaw := firstNonEmpty(
		os.Getenv("OCCLUDRA_UPSTREAM_BASE_URL"),
		policy.Upstream.BaseURL,
		"https://opencode.ai/zen/v1",
	)
	base, err := url.Parse(upstreamRaw)
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" {
		log.Fatalf("invalid upstream base URL %q: %v", upstreamRaw, err)
	}
	key := firstNonEmpty(
		os.Getenv("OCCLUDRA_UPSTREAM_API_KEY"),
		os.Getenv("OPENCODE_API_KEY"),
		os.Getenv("ANTHROPIC_API_KEY"),
	)

	// Optional secondary provider (upstream SPOF elimination): a distinct
	// base URL + its own key. Example: primary OpenCode Zen, fallback
	// Anthropic direct — on Zen outage/429 the gateway retries there.
	var fallbackBase *url.URL
	var fallbackKey string
	if raw := strings.TrimSpace(os.Getenv("OCCLUDRA_FALLBACK_UPSTREAM_BASE_URL")); raw != "" {
		fallbackBase, err = url.Parse(raw)
		if err != nil || fallbackBase == nil || fallbackBase.Scheme == "" || fallbackBase.Host == "" {
			log.Fatalf("invalid fallback upstream base URL %q: %v", raw, err)
		}
		fallbackKey = firstNonEmpty(
			os.Getenv("OCCLUDRA_FALLBACK_API_KEY"),
			os.Getenv("ANTHROPIC_API_KEY"),
		)
		log.Printf("upstream failover enabled: %s → %s", base, fallbackBase)
	}

	g := &gateway{
		policyPath:   policyPath,
		upstreamBase: base,
		upstreamKey:  key,
		fallbackBase: fallbackBase,
		fallbackKey:  fallbackKey,
		inflight:     newInflightLimiter(envInt("OCCLUDRA_MAX_INFLIGHT", 64)),
		client: &http.Client{
			// SSE completions legitimately stream for minutes; the timeout
			// bounds the WHOLE request including body read, so it stays
			// generous — but bounded, unlike an unset client.
			Timeout: 10 * time.Minute,
			Transport: &http.Transport{
				// Defaults give 2 idle conns per host; under agent
				// concurrency every request above that churns a fresh TCP+
				// TLS handshake against the upstream.
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", g.serve)

	// Long WriteTimeout would cut streaming responses mid-flight; the other
	// server timeouts still bound slowloris-style connection holds.
	server := &http.Server{
		Addr:              envOr("OCCLUDRA_LISTEN", "0.0.0.0:8080"),
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: drain in-flight LLM streams on SIGTERM/SIGINT within
	// the pod's 30s terminationGracePeriodSeconds instead of hard-cutting them.
	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-shutdownCtx.Done()
		log.Printf("shutdown signal received; draining in-flight requests")
		drainCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := server.Shutdown(drainCtx); err != nil {
			log.Printf("graceful shutdown incomplete: %v", err)
			_ = server.Close()
		}
	}()

	addr := server.Addr
	log.Printf("occludra gateway listening on %s → upstream %s (policy %s, %d detectors)",
		addr, base, policyPath, len(policy.Detectors))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Policy{DefaultAction: "redact", RedactionToken: "[REDACTED]"}
	if err := yaml.Unmarshal(raw, p); err != nil {
		return nil, err
	}
	for i := range p.Detectors {
		d := &p.Detectors[i]
		if d.Action == "" {
			d.Action = p.DefaultAction
		}
		if d.Type != "" && d.Type != "regex" {
			return nil, fmt.Errorf("detector %q: unsupported type %q", d.Name, d.Type)
		}
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			return nil, fmt.Errorf("detector %q: %w", d.Name, err)
		}
		d.re = re
	}
	for _, pattern := range p.Models.Allow {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("model allow pattern %q: %w", pattern, err)
		}
		p.Models.re = append(p.Models.re, re)
	}
	return p, nil
}

// serve handles everything under "/". Redaction applies to BOTH inference
// wire formats providers use — the classic /chat/completions AND the OpenAI
// Responses API /responses (OpenCode's provider client uses the latter).
// Redaction is shape-agnostic (recursive string walk), so both bodies are
// handled by the same routine; everything else proxies verbatim.
func (g *gateway) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost &&
		(strings.HasSuffix(r.URL.Path, "/chat/completions") || strings.HasSuffix(r.URL.Path, "/responses")) {
		g.serveChatCompletions(w, r)
		return
	}
	g.proxy(w, r, nil, 0)
}

func (g *gateway) serveChatCompletions(w http.ResponseWriter, r *http.Request) {
	stats := &requestStats{redactions: map[string]int{}}
	policy := g.currentPolicy(nil)

	// Backpressure before reading the body: at saturation answer 503 +
	// Retry-After (evaluator and OpenCode clients retry with backoff)
	// instead of buffering unlimited concurrent request bodies and SSE
	// streams — memory, not CPU, is what runs out first under load.
	if !g.inflight.acquire(2 * time.Second) {
		log.Printf("saturated (%d in-flight); rejecting with 503", g.inflight.used)
		w.Header().Set("Retry-After", "3")
		http.Error(w, "gateway at capacity; retry with backoff", http.StatusServiceUnavailable)
		return
	}
	defer g.inflight.release()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf("body too large or unreadable: %v", err), http.StatusRequestEntityTooLarge)
		return
	}

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "request body is not valid JSON", http.StatusBadRequest)
		return
	}
	obj, ok := payload.(map[string]any)
	if !ok {
		http.Error(w, "request body is not a JSON object", http.StatusBadRequest)
		return
	}
	if m, ok := obj["model"].(string); ok {
		stats.model = m
	}
	if !g.modelAllowed(policy, stats.model) {
		log.Printf("blocked model %q: not in allowlist", stats.model)
		http.Error(w, fmt.Sprintf("model %q is not allowed by gateway policy", stats.model), http.StatusForbidden)
		return
	}

	redactValue(obj, policy, stats)
	if stats.blockedBy != "" {
		log.Printf("blocked request (model %q): detector %q matched with action=block", stats.model, stats.blockedBy)
		http.Error(w, "request blocked by gateway policy", http.StatusForbidden)
		return
	}
	normalizeToolChoice(obj)

	redacted, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "failed to re-encode request", http.StatusInternalServerError)
		return
	}
	if policy.Logging.LogRedactions {
		total := 0
		for _, n := range stats.redactions {
			total += n
		}
		if total > 0 {
			log.Printf("model %q: %d redaction(s) %v", stats.model, total, formatRedactions(stats))
		}
	}
	g.proxy(w, r, redacted, int64(len(redacted)))
}

// redactValue walks the JSON tree and redacts every string value. Strings
// are rewritten by their owning map/slice via redactString (Go strings are
// immutable), so only containers are handled here.
func redactValue(v any, p *Policy, stats *requestStats) {
	switch typed := v.(type) {
	case []any:
		for i, item := range typed {
			if s, ok := item.(string); ok {
				typed[i] = redactString(s, p, stats)
				continue
			}
			redactValue(item, p, stats)
		}
	case map[string]any:
		for key, item := range typed {
			if s, ok := item.(string); ok {
				typed[key] = redactString(s, p, stats)
				continue
			}
			redactValue(item, p, stats)
		}
	}
}

func redactString(s string, p *Policy, stats *requestStats) string {
	out := s
	for i := range p.Detectors {
		d := &p.Detectors[i]
		if d.re == nil || !d.re.MatchString(out) {
			continue
		}
		if d.Action == "block" {
			if stats.blockedBy == "" {
				stats.blockedBy = d.Name
			}
			continue
		}
		stats.redactions[d.Name]++
		out = d.re.ReplaceAllString(out, p.RedactionToken)
	}
	return out
}

func (g *gateway) modelAllowed(p *Policy, model string) bool {
	if len(p.Models.re) == 0 {
		return true
	}
	for _, re := range p.Models.re {
		if re.MatchString(model) {
			return true
		}
	}
	return false
}

// normalizeToolChoice rewrites unsupported tool_choice values to "auto".
// OpenCode's structured-output mechanism emits tool_choice "none" (and some
// clients emit "required" or named-function choices), which OpenCode Zen's
// free tier rejects with 400 — only "auto" is accepted there. "auto" is also
// what the OpenCode CLI itself sends, so this mirrors the known-good wire
// shape. Purely mechanical: it neither adds nor removes tools.
func normalizeToolChoice(obj map[string]any) {
	tc, ok := obj["tool_choice"]
	if !ok || tc == nil {
		return
	}
	if s, ok := tc.(string); ok && s == "auto" {
		return
	}
	obj["tool_choice"] = "auto"
	log.Printf("tool_choice normalized to \"auto\"")
}

// proxy forwards the (possibly rewritten) request to the upstream provider
// and streams the response back, flushing per chunk so SSE stays live.
// OCCLUDRA_UPSTREAM_BASE_URL carries any upstream path prefix (e.g.
// https://opencode.ai/zen/v1); a leading "/v1" on the incoming path is the
// gateway's own route prefix and is stripped before joining.
//
// Upstream failover: when a secondary provider is configured
// (OCCLUDRA_FALLBACK_UPSTREAM_BASE_URL), a transport error, 429 or 5xx from
// the primary is retried against it — only before any byte reaches the
// client, so streaming responses are never duplicated mid-flight. Requests
// are NOT retried on 4xx (model-not-found etc. is a request problem, and
// POSTs are not idempotent beyond this one deliberate hop).
func (g *gateway) proxy(w http.ResponseWriter, r *http.Request, body []byte, contentLength int64) {
	incoming := r.URL.Path
	if incoming == "/v1" {
		incoming = ""
	} else if strings.HasPrefix(incoming, "/v1/") {
		incoming = strings.TrimPrefix(incoming, "/v1")
	}

	type upstream struct {
		name string
		base *url.URL
		key  string
	}
	targets := []upstream{{name: "primary", base: g.upstreamBase, key: g.upstreamKey}}
	if g.fallbackBase != nil {
		targets = append(targets, upstream{name: "fallback", base: g.fallbackBase, key: g.fallbackKey})
	}

	var resp *http.Response
	servedBy := targets[0].name
	for i, target := range targets {
		upstreamURL := strings.TrimSuffix(target.base.String(), "/") + incoming
		if r.URL.RawQuery != "" {
			upstreamURL += "?" + r.URL.RawQuery
		}
		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
		if err != nil {
			http.Error(w, fmt.Sprintf("building upstream request: %v", err), http.StatusInternalServerError)
			return
		}
		for name, values := range r.Header {
			if isHopByHop(name) || strings.EqualFold(name, "Authorization") {
				continue
			}
			for _, v := range values {
				upReq.Header.Add(name, v)
			}
		}
		if target.key != "" {
			upReq.Header.Set("Authorization", "Bearer "+target.key)
		}
		if body != nil {
			upReq.ContentLength = contentLength
			upReq.Header.Set("Content-Length", fmt.Sprintf("%d", contentLength))
		}

		resp, err = g.client.Do(upReq)
		last := i == len(targets)-1
		if err == nil && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			servedBy = target.name
			break
		}
		// Primary failed with a retryable class — the fallback exists to
		// absorb exactly this. Close the dead response before moving on.
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			resp = nil
		}
		if last {
			if err != nil {
				log.Printf("upstream %s error: %v", target.name, err)
				http.Error(w, "upstream request failed", http.StatusBadGateway)
			}
			break
		}
		log.Printf("upstream %s unavailable (err=%v); failing over to secondary provider", target.name, err)
	}
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	log.Printf("served via upstream %s (status %d)", servedBy, resp.StatusCode)

	isInference := markerApplies(incoming)
	isSSE := strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")

	// Non-streaming JSON inference response: buffer (bounded), append the
	// marker to the last message, forward.
	if responseMarkerEnabled() && isInference && !isSSE {
		limited := io.LimitReader(resp.Body, maxBodyBytes)
		bodyBytes, err := io.ReadAll(limited)
		if err != nil {
			http.Error(w, "reading upstream response failed", http.StatusBadGateway)
			return
		}
		bodyBytes = appendMarkerToJSON(bodyBytes)
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
		w.Header().Set("X-Occludra-Proxy", "true")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(bodyBytes)
		return
	}

	for name, values := range resp.Header {
		if isHopByHop(name) || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	if responseMarkerEnabled() && isInference {
		w.Header().Set("X-Occludra-Proxy", "true")
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	if isSSE && responseMarkerEnabled() && isInference {
		// Line-oriented pass-through with terminal-event interception —
		// the stream stays live, only the final event is held back long
		// enough to inject the marker before it.
		injector := newSSEMarkerInjector(isInference)
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), maxBodyBytes)
		for scanner.Scan() {
			for _, out := range injector.transform(scanner.Text()) {
				fmt.Fprintln(w, out)
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		return
	}
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			return
		}
	}
}

// responseMarker is the append-detection feature: every response that comes
// back THROUGH the gateway gets " (proxy)" appended to the last message, so
// clients can visually verify their LLM traffic never went direct to the
// provider. Controlled by OCCLUDRA_RESPONSE_MARKER (default on).
const responseMarkerText = " (proxy)"

func responseMarkerEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("OCCLUDRA_RESPONSE_MARKER"))
	return raw == "" || !(raw == "0" || raw == "false" || raw == "no" || raw == "off")
}

// markerApplies reports whether the request path is one whose responses
// carry model text (the two inference wire formats; everything else —
// /models, health, etc. — is passed through untouched).
func markerApplies(incoming string) bool {
	return strings.HasSuffix(incoming, "/chat/completions") || strings.HasSuffix(incoming, "/responses")
}

// appendMarkerToJSON mutates a non-streaming inference response in place:
// chat.completions → choices[last].message.content; responses API → the last
// output_text entry. Unknown shapes pass through unchanged.
func appendMarkerToJSON(body []byte) []byte {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	changed := false
	if choices, ok := payload["choices"].([]any); ok && len(choices) > 0 {
		if choice, ok := choices[len(choices)-1].(map[string]any); ok {
			if msg, ok := choice["message"].(map[string]any); ok {
				if content, ok := msg["content"].(string); ok {
					msg["content"] = content + responseMarkerText
					changed = true
				}
			}
		}
	}
	if outputs, ok := payload["output"].([]any); ok && len(outputs) > 0 {
		for i := len(outputs) - 1; i >= 0 && !changed; i-- {
			item, ok := outputs[i].(map[string]any)
			if !ok {
				continue
			}
			contents, ok := item["content"].([]any)
			if !ok {
				continue
			}
			for j := len(contents) - 1; j >= 0 && !changed; j-- {
				part, ok := contents[j].(map[string]any)
				if !ok || part["type"] != "output_text" {
					continue
				}
				if text, ok := part["text"].(string); ok {
					part["text"] = text + responseMarkerText
					changed = true
				}
			}
		}
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
}

// sseMarkerInjector rewrites a chat-completions/responses SSE stream so the
// LAST text the client renders carries the marker. It never buffers the
// stream: lines pass through immediately except the terminal events, which
// are intercepted and preceded by an injected marker event.
//
//   - chat.completions: before `data: [DONE]` an extra chunk with a content
//     delta is emitted.
//   - responses API: before the `response.completed` event, an
//     output_text.delta echoing the item ids of the previous real delta is
//     emitted, AND the completed snapshot's final text is mutated in place.
type sseMarkerInjector struct {
	inferencePath bool
	// last real output_text.delta fields, reused for the injected one.
	itemID      string
	outputIndex any
	contentInd  any
	sawDeltas   bool
	// completedSeen: the `event: response.completed` line was just passed —
	// its data line must be mutated but NOT re-injected (the marker delta
	// goes out exactly once, before the event block).
	completedSeen bool
}

func newSSEMarkerInjector(inferencePath bool) *sseMarkerInjector {
	return &sseMarkerInjector{inferencePath: inferencePath}
}

// transform receives one line (with its trailing newline already stripped)
// and returns zero or more lines to write, in order.
func (m *sseMarkerInjector) transform(line string) []string {
	if !m.inferencePath {
		return []string{line}
	}
	trimmed := strings.TrimSpace(line)

	// Track the ids of the most recent real text delta (responses API).
	if data, ok := strings.CutPrefix(trimmed, "data:"); ok {
		var ev struct {
			Type        string `json:"type"`
			ItemID      string `json:"item_id"`
			OutputIndex any    `json:"output_index"`
			ContentInd  any    `json:"content_index"`
			Delta       any    `json:"delta"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(data)), &ev) == nil && ev.Type == "response.output_text.delta" {
			m.itemID, m.outputIndex, m.contentInd, m.sawDeltas = ev.ItemID, ev.OutputIndex, ev.ContentInd, true
		}
	}

	isChatDone := trimmed == "data: [DONE]"
	isCompletedEventLine := strings.HasPrefix(trimmed, "event: response.completed")
	isCompletedDataLine := strings.HasPrefix(trimmed, "data: {") && strings.Contains(trimmed, `"type":"response.completed"`)
	if !isChatDone && !isCompletedEventLine && !isCompletedDataLine {
		m.completedSeen = false
		return []string{line}
	}

	var injected []string
	if isChatDone {
		chunk := map[string]any{
			"id":      "occludra-proxy-marker",
			"object":  "chat.completion.chunk",
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": responseMarkerText}, "finish_reason": nil}},
		}
		b, _ := json.Marshal(chunk)
		injected = append(injected, "data: "+string(b), "")
	} else if isCompletedEventLine {
		// responses API: emit the marker delta before the completed event
		// block, then fall through so the snapshot data line below is
		// mutated in place.
		if m.sawDeltas || m.itemID != "" {
			delta := map[string]any{
				"type":          "response.output_text.delta",
				"item_id":       m.itemID,
				"output_index":  m.outputIndex,
				"content_index": m.contentInd,
				"delta":         responseMarkerText,
			}
			if m.itemID == "" {
				delete(delta, "item_id")
			}
			b, _ := json.Marshal(delta)
			injected = append(injected, "event: response.output_text.delta", "data: "+string(b), "")
		}
		m.completedSeen = true
		return append(injected, line)
	} else if !m.completedSeen {
		// data line carrying response.completed without an event line
		// (stream style without event framing): inject once, then mutate.
		if m.sawDeltas || m.itemID != "" {
			delta := map[string]any{
				"type":          "response.output_text.delta",
				"item_id":       m.itemID,
				"output_index":  m.outputIndex,
				"content_index": m.contentInd,
				"delta":         responseMarkerText,
			}
			if m.itemID == "" {
				delete(delta, "item_id")
			}
			b, _ := json.Marshal(delta)
			injected = append(injected, "event: response.output_text.delta", "data: "+string(b), "")
		}
	}
	m.completedSeen = false

	if isCompletedDataLine {
		// Mutate the completed snapshot's final text too: clients that take
		// the authoritative text from response.completed see the marker
		// even if they drop the injected orphan delta.
		var snapshot map[string]any
		data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if json.Unmarshal([]byte(data), &snapshot) == nil {
			if snapResp, ok := snapshot["response"].(map[string]any); ok {
				if outputs, ok := snapResp["output"].([]any); ok {
					for i := len(outputs) - 1; i >= 0; i-- {
						item, ok := outputs[i].(map[string]any)
						if !ok {
							continue
						}
						contents, ok := item["content"].([]any)
						if !ok {
							continue
						}
						done := false
						for j := len(contents) - 1; j >= 0 && !done; j-- {
							part, ok := contents[j].(map[string]any)
							if !ok || part["type"] != "output_text" {
								continue
							}
							if text, ok := part["text"].(string); ok {
								part["text"] = text + responseMarkerText
								done = true
							}
						}
						if done {
							if b, err := json.Marshal(snapshot); err == nil {
								line = "data: " + string(b)
							}
							break
						}
					}
				}
			}
		}
	}
	return append(injected, line)
}

func isHopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

func formatRedactions(stats *requestStats) string {
	parts := make([]string, 0, len(stats.redactions))
	for name, n := range stats.redactions {
		parts = append(parts, fmt.Sprintf("%s=%d", name, n))
	}
	return strings.Join(parts, ",")
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
