/**
 * Schema-driven and protocol-level fuzzing of a live MCP server.
 */

import { Logger, rootLogger } from "./logger.js";
import { McpClient, extractText, isToolError } from "./mcpclient.js";
import {
  FuzzCase,
  FuzzCaseResult,
  FuzzCategory,
  FuzzErrorClass,
  FuzzReport,
  JsonSchema,
  McpToolDefinition,
  NotableResponse,
  RpcOutcome,
  isRecord,
} from "./types.js";

// ---------------------------------------------------------------------------
// Payload corpora
// ---------------------------------------------------------------------------

const BOUNDARY_NUMBERS: number[] = [0, -1, 1, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 1e308, 0.000001];
const PATH_TRAVERSAL: string[] = [
  "../../etc/passwd",
  "../../../../../../etc/passwd",
  "/etc/passwd",
  "..\\..\\windows\\win.ini",
  "/proc/self/environ",
  "file:///etc/passwd",
  "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
];
const COMMAND_INJECTION: string[] = ["; id", "$(id)", "`id`", "| id", "&& id", "'; id; '", "\n id \n", "$(sleep 3)"];
const UNICODE_STRINGS: string[] = [
  "\u202Eevil\u202C",
  "caf\u00e9\u0301",
  "\u0000null-byte",
  "a\u200Bb\u200Cc\u200Dd",
  "\uFFFD\uFFFE",
  "😀🔥💥".repeat(16),
  "\u0645\u0631\u062d\u0628\u0627",
];
const PROTOTYPE_KEYS: string[] = ["__proto__", "constructor", "prototype"];

function bigString(size: number): string {
  return "A".repeat(size);
}

function deepObject(depth: number): unknown {
  let current: unknown = { leaf: true };
  for (let i = 0; i < depth; i++) {
    current = { nested: current };
  }
  return current;
}

function hugeArray(length: number): number[] {
  const out: number[] = new Array<number>(length);
  for (let i = 0; i < length; i++) {
    out[i] = i;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

interface PropertyInfo {
  name: string;
  schema: JsonSchema;
  type: string;
  required: boolean;
}

function schemaType(schema: JsonSchema): string {
  const t = schema["type"];
  if (typeof t === "string") {
    return t;
  }
  if (Array.isArray(t) && typeof t[0] === "string") {
    return t[0];
  }
  if (Array.isArray(schema["enum"])) {
    return "string";
  }
  if (isRecord(schema["properties"])) {
    return "object";
  }
  if (schema["items"] !== undefined) {
    return "array";
  }
  return "string";
}

export function listProperties(schema: JsonSchema | undefined): PropertyInfo[] {
  if (!schema) {
    return [];
  }
  const props = isRecord(schema["properties"]) ? schema["properties"] : {};
  const requiredRaw = Array.isArray(schema["required"]) ? schema["required"] : [];
  const required = new Set<string>();
  for (const r of requiredRaw) {
    if (typeof r === "string") {
      required.add(r);
    }
  }
  const out: PropertyInfo[] = [];
  for (const [name, value] of Object.entries(props)) {
    const propSchema: JsonSchema = isRecord(value) ? value : {};
    out.push({ name, schema: propSchema, type: schemaType(propSchema), required: required.has(name) });
  }
  return out;
}

/** Produces a minimal, well-typed value satisfying (roughly) the schema. */
export function benignValue(schema: JsonSchema, depth = 0): unknown {
  if (depth > 6) {
    return null;
  }
  if (schema["example"] !== undefined) {
    return schema["example"];
  }
  if (Array.isArray(schema["examples"]) && schema["examples"].length > 0) {
    return schema["examples"][0];
  }
  if (schema["default"] !== undefined) {
    return schema["default"];
  }
  if (Array.isArray(schema["enum"]) && schema["enum"].length > 0) {
    return schema["enum"][0];
  }
  if (schema["const"] !== undefined) {
    return schema["const"];
  }
  const anyOf = schema["anyOf"] ?? schema["oneOf"];
  if (Array.isArray(anyOf) && anyOf.length > 0 && isRecord(anyOf[0])) {
    return benignValue(anyOf[0], depth + 1);
  }
  switch (schemaType(schema)) {
    case "string": {
      const format = typeof schema["format"] === "string" ? schema["format"] : "";
      const min = typeof schema["minLength"] === "number" ? schema["minLength"] : 0;
      if (format === "uri" || format === "url") {
        return "http://127.0.0.1/";
      }
      if (format === "email") {
        return "user@example.com";
      }
      if (format === "date-time") {
        return "2024-01-01T00:00:00Z";
      }
      if (format === "date") {
        return "2024-01-01";
      }
      const base = "example";
      return base.length >= min ? base : base + "x".repeat(min - base.length);
    }
    case "integer":
    case "number": {
      const min = typeof schema["minimum"] === "number" ? schema["minimum"] : undefined;
      const max = typeof schema["maximum"] === "number" ? schema["maximum"] : undefined;
      if (min !== undefined && min > 1) {
        return min;
      }
      if (max !== undefined && max < 1) {
        return max;
      }
      return 1;
    }
    case "boolean":
      return false;
    case "null":
      return null;
    case "array": {
      const items = isRecord(schema["items"]) ? schema["items"] : {};
      const minItems = typeof schema["minItems"] === "number" ? schema["minItems"] : 0;
      const arr: unknown[] = [];
      for (let i = 0; i < Math.max(1, Math.min(minItems, 3)); i++) {
        arr.push(benignValue(items, depth + 1));
      }
      return arr;
    }
    case "object": {
      const obj: Record<string, unknown> = {};
      for (const prop of listProperties(schema)) {
        if (prop.required || depth === 0) {
          obj[prop.name] = benignValue(prop.schema, depth + 1);
        }
      }
      return obj;
    }
    default:
      return "example";
  }
}

export function benignArgs(tool: McpToolDefinition): Record<string, unknown> {
  const value = benignValue(tool.inputSchema ?? { type: "object", properties: {} });
  return isRecord(value) ? value : {};
}

function mismatchedValue(type: string): unknown {
  switch (type) {
    case "string":
      return 12345;
    case "integer":
    case "number":
      return "not-a-number";
    case "boolean":
      return "true";
    case "array":
      return { not: "an array" };
    case "object":
      return "not-an-object";
    default:
      return [1, 2, 3];
  }
}

// ---------------------------------------------------------------------------
// Case generation
// ---------------------------------------------------------------------------

export interface FuzzOptions {
  maxCasesPerTool?: number;
  totalTimeBudgetMs?: number;
  perCallTimeoutMs?: number;
  includeProtocolCases?: boolean;
}

export function generateFuzzCases(tool: McpToolDefinition, maxCases: number): FuzzCase[] {
  const cases: FuzzCase[] = [];
  const schema = tool.inputSchema ?? { type: "object", properties: {} };
  const props = listProperties(schema);
  const base = benignArgs(tool);
  let counter = 0;
  const add = (category: FuzzCategory, description: string, args: unknown): void => {
    if (cases.length >= maxCases) {
      return;
    }
    counter += 1;
    cases.push({ id: `${tool.name}#${counter}`, tool: tool.name, category, description, args });
  };
  const withProp = (name: string, value: unknown): Record<string, unknown> => ({ ...base, [name]: value });

  // Null / missing for required properties
  for (const p of props.filter((x) => x.required)) {
    add("null-required", `required "${p.name}" = null`, withProp(p.name, null));
    const missing: Record<string, unknown> = { ...base };
    delete missing[p.name];
    add("missing-required", `required "${p.name}" omitted`, missing);
  }
  add("null-required", "arguments = null", null);
  add("missing-required", "arguments = {}", {});

  // Type mismatches
  for (const p of props) {
    add("type-mismatch", `"${p.name}" (${p.type}) given ${typeof mismatchedValue(p.type)}`, withProp(p.name, mismatchedValue(p.type)));
  }

  // Boundary values
  for (const p of props) {
    if (p.type === "integer" || p.type === "number") {
      for (const n of BOUNDARY_NUMBERS) {
        add("boundary", `"${p.name}" = ${n}`, withProp(p.name, n));
      }
      add("boundary", `"${p.name}" = NaN-as-string`, withProp(p.name, "NaN"));
    } else if (p.type === "string") {
      add("boundary", `"${p.name}" = ""`, withProp(p.name, ""));
      add("oversize", `"${p.name}" = 64KB string`, withProp(p.name, bigString(64 * 1024)));
      for (const s of PATH_TRAVERSAL) {
        add("path-traversal", `"${p.name}" = ${JSON.stringify(s)}`, withProp(p.name, s));
      }
      for (const s of COMMAND_INJECTION) {
        add("command-injection", `"${p.name}" = ${JSON.stringify(s)}`, withProp(p.name, s));
      }
      for (const s of UNICODE_STRINGS) {
        add("unicode", `"${p.name}" = ${JSON.stringify(s)}`, withProp(p.name, s));
      }
    } else if (p.type === "array") {
      add("boundary", `"${p.name}" = []`, withProp(p.name, []));
      add("oversize", `"${p.name}" = 100k-element array`, withProp(p.name, hugeArray(100000)));
    } else if (p.type === "object") {
      add("boundary", `"${p.name}" = {}`, withProp(p.name, {}));
      add("deep-nesting", `"${p.name}" = 500-deep nested object`, withProp(p.name, deepObject(500)));
    } else if (p.type === "boolean") {
      add("type-mismatch", `"${p.name}" = 1`, withProp(p.name, 1));
    }
  }

  // Extra props / prototype pollution (applied to every tool)
  add("extra-props", "unexpected extra property", { ...base, __unexpected_extra__: "x", zzz: 1 });
  for (const key of PROTOTYPE_KEYS) {
    add("prototype-pollution", `key "${key}" injected`, { ...base, [key]: { polluted: true } });
  }
  add("deep-nesting", "arguments = 500-deep nested object", deepObject(500));
  add("oversize", "arguments with 64KB string in every string prop", (() => {
    const o: Record<string, unknown> = { ...base };
    for (const p of props) {
      if (p.type === "string") {
        o[p.name] = bigString(64 * 1024);
      }
    }
    return o;
  })());

  return cases.slice(0, maxCases);
}

export interface ProtocolCase {
  id: string;
  description: string;
  rawFrame: string;
  expectId?: string | number;
}

export function generateProtocolCases(): ProtocolCase[] {
  const cases: ProtocolCase[] = [];
  cases.push({ id: "proto#1", description: "malformed JSON (truncated)", rawFrame: '{"jsonrpc":"2.0","id":9001,"method":"tools/list"' });
  cases.push({ id: "proto#2", description: "not JSON at all", rawFrame: "this is not json" });
  cases.push({ id: "proto#3", description: "missing jsonrpc field", rawFrame: JSON.stringify({ id: 9003, method: "tools/list", params: {} }), expectId: 9003 });
  cases.push({ id: "proto#4", description: "wrong jsonrpc version", rawFrame: JSON.stringify({ jsonrpc: "1.0", id: 9004, method: "tools/list", params: {} }), expectId: 9004 });
  cases.push({ id: "proto#5", description: "unknown method", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9005, method: "evaluator/does_not_exist", params: {} }), expectId: 9005 });
  cases.push({ id: "proto#6", description: "id as object (invalid type)", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: { bad: true }, method: "tools/list", params: {} }) });
  cases.push({ id: "proto#7", description: "id as float", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9007.5, method: "tools/list", params: {} }) });
  cases.push({ id: "proto#8", description: "batch request", rawFrame: JSON.stringify([
    { jsonrpc: "2.0", id: 9008, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 9009, method: "prompts/list", params: {} },
  ]), expectId: 9008 });
  cases.push({ id: "proto#9", description: "params as array instead of object", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9010, method: "tools/call", params: ["a", "b"] }), expectId: 9010 });
  cases.push({ id: "proto#10", description: "method as number", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9011, method: 42, params: {} }), expectId: 9011 });
  cases.push({ id: "proto#11", description: "oversized frame (1MB)", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9012, method: "tools/call", params: { name: "x", arguments: { pad: bigString(1024 * 1024) } } }), expectId: 9012 });
  cases.push({ id: "proto#12", description: "empty object", rawFrame: "{}" });
  cases.push({ id: "proto#13", description: "notification with id null", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: null, method: "tools/list", params: {} }) });
  cases.push({ id: "proto#14", description: "tools/call missing name", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9014, method: "tools/call", params: { arguments: {} } }), expectId: 9014 });
  cases.push({ id: "proto#15", description: "tools/call unknown tool", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9015, method: "tools/call", params: { name: "__evaluator_nonexistent_tool__", arguments: {} } }), expectId: 9015 });
  cases.push({ id: "proto#16", description: "resources/read invalid uri", rawFrame: JSON.stringify({ jsonrpc: "2.0", id: 9016, method: "resources/read", params: { uri: "file:///etc/passwd" } }), expectId: 9016 });
  return cases;
}

// ---------------------------------------------------------------------------
// Response inspection
// ---------------------------------------------------------------------------

const LEAK_PATTERNS: { reason: string; regex: RegExp }[] = [
  { reason: "stack trace leaked", regex: /(at\s+\S+\s+\(.*:\d+:\d+\))|Traceback \(most recent call last\)|goroutine \d+ \[/ },
  { reason: "absolute filesystem path leaked", regex: /(\/home\/[a-z0-9_-]+\/|\/usr\/(lib|local)\/|\/workspace\/|C:\\Users\\)/i },
  { reason: "environment variable content leaked", regex: /(PATH=|HOME=|KUBERNETES_SERVICE_HOST|AWS_SECRET_ACCESS_KEY|ANTHROPIC_API_KEY|OPENCODE_API_KEY)/ },
  { reason: "command injection payload executed (uid output)", regex: /uid=\d+\(\w+\)\s+gid=\d+/ },
  { reason: "/etc/passwd content returned", regex: /root:x:0:0:/ },
  { reason: "internal error details leaked", regex: /(ECONNREFUSED|ENOENT: no such file|SyntaxError: Unexpected token|TypeError: Cannot read)/ },
];

function inspectResponse(text: string, fuzzCase: FuzzCase): NotableResponse[] {
  const notes: NotableResponse[] = [];
  for (const { reason, regex } of LEAK_PATTERNS) {
    const match = regex.exec(text);
    if (match) {
      const idx = Math.max(0, match.index - 80);
      notes.push({ caseId: fuzzCase.id, tool: fuzzCase.tool, reason, excerpt: text.slice(idx, idx + 240) });
    }
  }
  if (fuzzCase.category === "path-traversal" && /root:x:0:0:|\[extensions\]|for 16-bit app support/.test(text)) {
    notes.push({ caseId: fuzzCase.id, tool: fuzzCase.tool, reason: "path traversal succeeded", excerpt: text.slice(0, 240) });
  }
  return notes;
}

function classify(outcome: RpcOutcome): FuzzErrorClass {
  if (outcome.crashed) {
    return "crash";
  }
  if (outcome.hang) {
    return "hang";
  }
  if (outcome.transportError === "malformed response") {
    return "malformed-response";
  }
  if (outcome.transportError && !outcome.ok && !outcome.error) {
    return "transport-error";
  }
  if (outcome.error) {
    return "jsonrpc-error";
  }
  if (isToolError(outcome.result)) {
    return "tool-error";
  }
  return "ok";
}

function emptyErrorCounts(): Record<FuzzErrorClass, number> {
  return { ok: 0, "jsonrpc-error": 0, "tool-error": 0, hang: 0, crash: 0, "transport-error": 0, "malformed-response": 0 };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export async function runFuzz(client: McpClient, tools: McpToolDefinition[], options: FuzzOptions = {}): Promise<FuzzReport> {
  const log: Logger = rootLogger.child("fuzz");
  const maxCasesPerTool = options.maxCasesPerTool ?? 25;
  const budgetMs = options.totalTimeBudgetMs ?? 4 * 60 * 1000;
  const perCallTimeoutMs = options.perCallTimeoutMs ?? 10000;
  const startedAt = Date.now();
  const results: FuzzCaseResult[] = [];
  const notable: NotableResponse[] = [];
  const errorsByClass = emptyErrorCounts();
  let crashes = 0;
  let hangs = 0;
  let budgetExhausted = false;

  const record = (fuzzCase: FuzzCase, outcome: RpcOutcome): void => {
    const errorClass = classify(outcome);
    errorsByClass[errorClass] += 1;
    if (errorClass === "crash") {
      crashes += 1;
    }
    if (errorClass === "hang") {
      hangs += 1;
    }
    let excerpt = "";
    if (outcome.result !== undefined) {
      const text = extractText(outcome.result);
      excerpt = text.slice(0, 300);
      notable.push(...inspectResponse(text, fuzzCase));
    } else if (outcome.error) {
      const text = `${outcome.error.message} ${JSON.stringify(outcome.error.data ?? "")}`;
      excerpt = text.slice(0, 300);
      notable.push(...inspectResponse(text, fuzzCase));
    }
    results.push({
      caseId: fuzzCase.id,
      tool: fuzzCase.tool,
      category: fuzzCase.category,
      description: fuzzCase.description,
      errorClass,
      latencyMs: outcome.latencyMs,
      errorCode: outcome.error?.code,
      errorMessage: outcome.error?.message ?? outcome.transportError,
      responseExcerpt: excerpt,
    });
  };

  const overBudget = (): boolean => Date.now() - startedAt > budgetMs;

  outer: for (const tool of tools) {
    const cases = generateFuzzCases(tool, maxCasesPerTool);
    log.info("fuzzing tool", { tool: tool.name, cases: cases.length });
    for (const fuzzCase of cases) {
      if (overBudget()) {
        budgetExhausted = true;
        break outer;
      }
      const outcome = await client.callTool(fuzzCase.tool, fuzzCase.args, perCallTimeoutMs);
      record(fuzzCase, outcome);
      if (outcome.crashed) {
        log.warn("target crashed during fuzz case; recovering", { caseId: fuzzCase.id });
        const recovered = await client.recover(30000);
        if (!recovered) {
          log.error("target did not recover after crash; stopping fuzz");
          break outer;
        }
      }
    }
  }

  if (options.includeProtocolCases !== false && !budgetExhausted) {
    for (const pc of generateProtocolCases()) {
      if (overBudget()) {
        budgetExhausted = true;
        break;
      }
      const fuzzCase: FuzzCase = { id: pc.id, tool: "<protocol>", category: "protocol", description: pc.description, rawFrame: pc.rawFrame };
      const outcome = await client.sendRaw(pc.rawFrame, Math.min(perCallTimeoutMs, 5000), pc.expectId);
      record(fuzzCase, outcome);
      if (outcome.crashed) {
        log.warn("target crashed during protocol case; recovering", { caseId: pc.id });
        const recovered = await client.recover(30000);
        if (!recovered) {
          log.error("target did not recover after protocol crash; stopping fuzz");
          break;
        }
      }
    }
  }

  const latency = client.latency.stats();
  return {
    cases: results,
    totalCases: results.length,
    crashes,
    hangs,
    errorsByClass,
    latency,
    notableResponses: notable.slice(0, 100),
    timeBudgetExhausted: budgetExhausted,
  };
}

export function renderFuzzMarkdown(report: FuzzReport): string {
  const lines: string[] = [];
  lines.push(`### Fuzzing summary`);
  lines.push(`- total cases: ${report.totalCases}`);
  lines.push(`- crashes: ${report.crashes}, hangs: ${report.hangs}, time budget exhausted: ${report.timeBudgetExhausted}`);
  lines.push(`- errors by class: ${JSON.stringify(report.errorsByClass)}`);
  lines.push(
    `- latency: count=${report.latency.count} avg=${report.latency.avgMs}ms p95=${report.latency.p95Ms}ms max=${report.latency.maxMs}ms`,
  );
  if (report.notableResponses.length > 0) {
    lines.push(`### Notable responses (${report.notableResponses.length})`);
    for (const n of report.notableResponses.slice(0, 40)) {
      lines.push(`- [${n.caseId}] ${n.tool}: ${n.reason} :: ${JSON.stringify(n.excerpt)}`);
    }
  }
  const byCategory = new Map<string, FuzzCaseResult[]>();
  for (const c of report.cases) {
    const key = `${c.tool}/${c.category}`;
    const list = byCategory.get(key) ?? [];
    list.push(c);
    byCategory.set(key, list);
  }
  lines.push(`### Per tool/category outcomes`);
  for (const [key, list] of byCategory.entries()) {
    const counts: Record<string, number> = {};
    for (const c of list) {
      counts[c.errorClass] = (counts[c.errorClass] ?? 0) + 1;
    }
    lines.push(`- ${key}: ${JSON.stringify(counts)}`);
  }
  const bad = report.cases.filter((c) => c.errorClass === "crash" || c.errorClass === "hang" || c.errorClass === "malformed-response");
  if (bad.length > 0) {
    lines.push(`### Crash / hang / malformed cases`);
    for (const c of bad.slice(0, 40)) {
      lines.push(`- [${c.caseId}] ${c.description} -> ${c.errorClass} (${c.latencyMs}ms) ${c.errorMessage ?? ""}`);
    }
  }
  return lines.join("\n");
}
