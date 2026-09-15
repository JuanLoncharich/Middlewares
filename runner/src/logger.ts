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
    if (value instanceof Error) {
      out[key] = { name: value.name, message: value.message, stack: value.stack };
    } else {
      out[key] = value;
    }
  }
  return out;
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
      msg,
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
