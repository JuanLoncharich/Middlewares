// Evaluator log lines: one JSON object per line on stderr, written by
// runner/src/logger.ts. The runner already redacts prompts, payloads and
// credentials before writing, so these lines are safe to show on screen.

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogLine {
  ts: string;
  level: LogLevel;
  component: string;
  msg: string;
  run?: string;
  namespace?: string;
  trace_id?: string;
  span_id?: string;
  [field: string]: unknown;
}

const RESERVED = new Set(["ts", "level", "component", "msg", "run", "namespace", "trace_id", "span_id"]);

/** Parses one log line; anything that is not the runner's JSON shape is dropped. */
export function parseLogLine(raw: string): LogLine | null {
  const text = raw.trim();
  if (!text.startsWith("{")) return null;
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object") return null;
  const rec = value as Record<string, unknown>;
  if (typeof rec["ts"] !== "string" || typeof rec["msg"] !== "string") return null;
  const level = rec["level"];
  return {
    ...rec,
    ts: rec["ts"],
    msg: rec["msg"],
    component: typeof rec["component"] === "string" ? rec["component"] : "evaluator",
    level: level === "debug" || level === "warn" || level === "error" ? level : "info",
  } as LogLine;
}

export function extraFields(line: LogLine): [string, unknown][] {
  return Object.entries(line).filter(([k]) => !RESERVED.has(k));
}

// ANSI colours; the xterm theme maps them onto the page palette.
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const LEVEL_STYLE: Record<LogLevel, string> = {
  debug: "\x1b[90m",
  info: "\x1b[36m",
  warn: "\x1b[33m",
  error: "\x1b[1;31m",
};

function formatValue(v: unknown): string {
  if (typeof v === "string") return /\s/.test(v) ? JSON.stringify(v) : v;
  return JSON.stringify(v);
}

/** One terminal row: time, level, component, message, key=value fields. */
export function formatForTerminal(line: LogLine): string {
  const d = new Date(line.ts);
  const time = Number.isNaN(d.getTime())
    ? line.ts
    : `${d.toLocaleTimeString("es-AR", { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`;
  const level = line.level.toUpperCase().padEnd(5);
  const fields = extraFields(line)
    .map(([k, v]) => `${DIM}${k}=${RESET}${formatValue(v)}`)
    .join(" ");
  return `${DIM}${time}${RESET} ${LEVEL_STYLE[line.level]}${level}${RESET} ${DIM}${line.component}${RESET} ${BOLD}${line.msg}${RESET}${fields ? "  " + fields : ""}`;
}
