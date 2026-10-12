package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var (
	requests       = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "occludra_requests_total", Help: "Gateway requests by bounded route and status."}, []string{"route", "status"})
	durations      = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "occludra_request_duration_seconds", Help: "Request duration including the full SSE stream.", Buckets: []float64{.1, .5, 1, 5, 15, 30, 60, 120, 300, 600}}, []string{"route"})
	activeRequests = prometheus.NewGauge(prometheus.GaugeOpts{Name: "occludra_active_requests", Help: "Currently handled gateway requests."})
	redactions     = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "occludra_redactions_total", Help: "Strings redacted by configured detector."}, []string{"detector"})
	blocked        = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "occludra_blocked_requests_total", Help: "Requests blocked by policy."}, []string{"reason"})
	failovers      = prometheus.NewCounter(prometheus.CounterOpts{Name: "occludra_upstream_failovers_total", Help: "Requests retried against the secondary provider."})
)

func init() {
	prometheus.MustRegister(requests, durations, activeRequests, redactions, blocked, failovers)
}

func setupTracing() func() {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" || os.Getenv("OTEL_SDK_DISABLED") == "true" {
		return func() {}
	}
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithTimeout(3*time.Second))
	if err != nil {
		slog.Warn("tracing setup failed", "error_type", fmt.Sprintf("%T", err))
		return func() {}
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())), sdktrace.WithResource(resource.NewSchemaless(
		attribute.String("service.name", "occludra"), attribute.String("k8s.namespace.name", os.Getenv("POD_NAMESPACE")), attribute.String("k8s.pod.name", os.Getenv("POD_NAME")),
	)))
	otel.SetTracerProvider(provider)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = provider.Shutdown(ctx)
	}
}

type jsonLogWriter struct{}

func (jsonLogWriter) Write(p []byte) (int, error) {
	slog.Info(strings.TrimSpace(string(p)), "component", "occludra")
	return len(p), nil
}

// Keep Flusher and ResponseController available: OpenCode relies on SSE.
type observedWriter struct {
	http.ResponseWriter
	status int
}

func (w *observedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *observedWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *observedWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
func (w *observedWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func routeName(path string) string {
	switch path {
	case "/v1/chat/completions", "/chat/completions":
		return "chat_completions"
	case "/v1/responses", "/responses":
		return "responses"
	case "/v1/models", "/models":
		return "models"
	default:
		return "other"
	}
}

func observeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		started := time.Now()
		route := routeName(r.URL.Path)
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer("occludra").Start(ctx, "occludra.request", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("http.route", route)))
		defer span.End()
		activeRequests.Inc()
		defer activeRequests.Dec()
		out := &observedWriter{ResponseWriter: w}
		next.ServeHTTP(out, r.WithContext(ctx))
		status := out.status
		if status == 0 {
			status = http.StatusOK
		}
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		if status >= 400 {
			span.SetStatus(codes.Error, "request failed")
		}
		requests.WithLabelValues(route, strconv.Itoa(status)).Inc()
		durations.WithLabelValues(route).Observe(time.Since(started).Seconds())
		sc := span.SpanContext()
		slog.Info("gateway request completed", "route", route, "status", status, "duration_seconds", time.Since(started).Seconds(), "trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String(), "component", "occludra")
	})
}
