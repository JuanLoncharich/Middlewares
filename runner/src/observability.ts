import { context, propagation, trace, SpanKind, SpanStatusCode, type Attributes, type Span } from "@opentelemetry/api";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { metrics } from "@opentelemetry/api";

let sdk: NodeSDK | undefined;

// Explicit instrumentation avoids capturing MCP payloads, file contents,
// prompts, provider credentials, HTTP query strings, or SDK response bodies.
export function startTelemetry(): void {
  const endpoint = process.env["OTEL_EXPORTER_OTLP_ENDPOINT"];
  if (!endpoint || process.env["OTEL_SDK_DISABLED"] === "true") return;
  try {
    const base = endpoint.replace(/\/$/, "");
    sdk = new NodeSDK({
      resource: resourceFromAttributes({
        "service.name": "mcp-evaluator",
        "service.instance.id": process.env["POD_NAME"] ?? process.env["RUN_NAME"] ?? "local",
        "k8s.namespace.name": process.env["RUN_NAMESPACE"] ?? "",
        "k8s.pod.name": process.env["POD_NAME"] ?? "",
      }),
      traceExporter: new OTLPTraceExporter({ url: `${base}/v1/traces`, timeoutMillis: 3000 }),
      metricReader: new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: `${base}/v1/metrics`, timeoutMillis: 3000 }),
        exportIntervalMillis: 10000,
        exportTimeoutMillis: 5000,
      }),
    });
    sdk.start();
  } catch { sdk = undefined; }
}

export async function stopTelemetry(): Promise<void> {
  // Jobs must flush before process.exit; a missing collector must not stall them.
  if (!sdk) return;
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([sdk.shutdown(), new Promise<void>((resolve) => { timer = setTimeout(resolve, 5000); })]);
  } catch { /* telemetry is best effort */ }
  finally { if (timer) clearTimeout(timer); }
}

export function traceFields(): Record<string, string> {
  const sc = trace.getSpan(context.active())?.spanContext();
  return sc && trace.isSpanContextValid(sc) ? { trace_id: sc.traceId, span_id: sc.spanId } : {};
}

export function requestTraceHeaders(): Record<string, string> {
  const carrier: Record<string, string> = {};
  propagation.inject(context.active(), carrier);
  for (const [env, header] of [["RUN_NAME", "x-mcp-run"], ["RUN_NAMESPACE", "x-mcp-namespace"]]) {
    const value = process.env[env!];
    if (value) carrier[header!] = value;
  }
  return carrier;
}

export async function inSpan<T>(name: string, attributes: Attributes, fn: (span: Span) => Promise<T>, kind = SpanKind.INTERNAL): Promise<T> {
  return trace.getTracer("mcp-evaluator").startActiveSpan(name, { attributes, kind }, async (span) => {
    try { return await fn(span); }
    catch (err) {
      span.setAttribute("error.type", err instanceof Error ? err.name : "UnknownError");
      span.setStatus({ code: SpanStatusCode.ERROR, message: "operation failed" });
      throw err;
    } finally { span.end(); }
  });
}

export async function evaluationTrace(fn: () => Promise<number>): Promise<number> {
  const parent = propagation.extract(context.active(), { traceparent: process.env["TRACEPARENT"] ?? "" });
  return context.with(parent, () => inSpan("evaluation.execute", {
    "mcp.run": process.env["RUN_NAME"] ?? "",
    "mcp.server": process.env["SERVER_NAME"] ?? "",
  }, async (span) => {
    const started = performance.now();
    const code = await fn();
    const outcome = code === 0 ? "completed" : "failed";
    span.setAttribute("mcp.outcome", outcome);
    if (code !== 0) span.setStatus({ code: SpanStatusCode.ERROR, message: "evaluation failed" });
    metrics.getMeter("mcp-evaluator").createHistogram("mcp.evaluator.duration", { unit: "s" })
      .record((performance.now() - started) / 1000, { outcome });
    return code;
  }));
}
