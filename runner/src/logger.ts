import { traceFields } from "./observability.js";
/**
 * Minimal structured JSON logger writing to stderr.
 * stdout is reserved so that it never interferes with any IPC.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function resolveLevel(): LogLevel {
  const raw = (process.env["LOG_LEVEL"] ?? "info").toLowerCase();
  if (raw === "debug" || raw === "info" || raw === "warn" || raw === "error") {
    return raw;
  }
  return "info";
}

const activeLevel: LogLevel = resolveLevel();

function safeSerialize(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = sanitize(value, key);
  }
  return out;
}

// Security evaluation evidence belongs in the access-controlled report,
// never in the shared observability store.
function sanitize(value: unknown, key = "", seen = new WeakSet<object>()): unknown {
  if (/prompt|payload|excerpt|structuredOutput|agentResults|authorization|password|api.?key|token|secret|body/i.test(key)) return "[REDACTED]";
  if (typeof value === "string") return value
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\b(?:sk-|nvapi-)[A-Za-z0-9_-]{12,}\b/g, "[REDACTED_KEY]")
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED_EMAIL]");
  if (value instanceof Error) return { name: value.name, message: sanitize(value.message) };
  if (value !== null && typeof value === "object") {
    if (seen.has(value)) return "[CIRCULAR]";
    seen.add(value);
    if (Array.isArray(value)) return value.map((item) => sanitize(item, "", seen));
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, sanitize(v, k, seen)]));
  }
  return value;
}

export class Logger {
  private readonly component: string;

  constructor(component: string) {
    this.component = component;
  }

  child(component: string): Logger {
    return new Logger(`${this.component}.${component}`);
  }

  debug(msg: string, fields: Record<string, unknown> = {}): void {
    this.write("debug", msg, fields);
  }

  info(msg: string, fields: Record<string, unknown> = {}): void {
    this.write("info", msg, fields);
  }

  warn(msg: string, fields: Record<string, unknown> = {}): void {
    this.write("warn", msg, fields);
  }

  error(msg: string, fields: Record<string, unknown> = {}): void {
    this.write("error", msg, fields);
  }

  private write(level: LogLevel, msg: string, fields: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[activeLevel]) {
      return;
    }
    const record = {
      ts: new Date().toISOString(),
      level,
      component: this.component,
      run: process.env["RUN_NAME"],
      namespace: process.env["RUN_NAMESPACE"],
      ...traceFields(),
      msg: sanitize(msg),
      ...safeSerialize(fields),
    };
    let line: string;
    try {
      line = JSON.stringify(record);
    } catch {
      line = JSON.stringify({ ts: record.ts, level, component: this.component, msg, serializeError: true });
    }
    process.stderr.write(line + "\n");
  }
}

export const rootLogger = new Logger("evaluator");
