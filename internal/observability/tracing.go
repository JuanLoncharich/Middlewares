package observability

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const TraceAnnotation = "security.eval.io/traceparent"

// Setup is opt-in. Exporter failures never interrupt reconciliation.
func Setup(service string) (func(), error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" || os.Getenv("OTEL_SDK_DISABLED") == "true" {
		return func() {}, nil
	}
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithTimeout(3*time.Second))
	if err != nil {
		return func() {}, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithMaxQueueSize(2048)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", service),
			attribute.String("k8s.namespace.name", os.Getenv("POD_NAMESPACE")),
			attribute.String("k8s.pod.name", os.Getenv("POD_NAME")),
		)),
	)
	otel.SetTracerProvider(provider)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = provider.Shutdown(ctx)
	}, nil
}

func Traceparent(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	return carrier["traceparent"]
}

func Extract(ctx context.Context, parent string) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier{"traceparent": parent})
}
