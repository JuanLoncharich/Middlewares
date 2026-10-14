/**
 * What the Vigil gates send: every untrusted text on its own, as plain text,
 * in chunks the scanner's classifier can read whole.
 *
 * Why not one JSON document per gate (the previous behaviour):
 *  - the transformer scanner (deberta-v3, 512-token window) scores a JSON
 *    blob as benign even when single fields score 1.0 as injection —
 *    measured on test/mcp-servers/mcp-evil-demo: the wrapped advertised
 *    surface came back clean, the weather description alone scored 1.0;
 *  - it reads at most 512 tokens, so anything past the first ~2 KB of a
 *    blob was never classified, and an untruncated 64 KB payload OOM-killed
 *    the scanner pod instead.
 *
 * Chunk size: the deberta-v3 tokenizer never produced more than one token
 * per character on any input we measured (prose/code ≈3.8 chars/token,
 * base64 1.4, punctuation runs, combining marks and space-separated CJK
 * 1.0). CHUNK_CHARS = 500 therefore stays within 512 tokens (510 + the two
 * special tokens) for any text; JS counts UTF-16 units, which is ≥ the code
 * points the tokenizer sees, so the bound holds for astral characters too.
 * Chunks overlap so a phrase cut by one boundary is seen whole in the next.
 */

import type {
  FuzzReport,
  JsonSchema,
  McpInitializeResult,
  McpPromptDefinition,
  McpResourceDefinition,
  McpToolDefinition,
  ProbeReport,
} from "./types.js";

export const CHUNK_CHARS = 500;
export const CHUNK_OVERLAP = 100;

/** One untrusted text with a human label saying where it came from. */
export interface ScanSegment {
  label: string;
  text: string;
}

export interface AdvertisedSurface {
  init: McpInitializeResult | null;
  tools: McpToolDefinition[];
  prompts: McpPromptDefinition[];
  resources: McpResourceDefinition[];
}

/** Gate 1: server instructions and every tool/prompt/resource text. */
export function surfaceSegments(surface: AdvertisedSurface): ScanSegment[] {
  const out: ScanSegment[] = [];
  push(out, "server instructions", surface.init?.instructions);
  const info = surface.init?.serverInfo;
  push(out, "server name", [info?.name, info?.version].filter(Boolean).join(" "));
  for (const tool of surface.tools) {
    push(out, `tool ${tool.name}: description`, joinNonEmpty(tool.name, tool.description));
    for (const [where, text] of schemaTexts(tool.inputSchema, "input")) {
      push(out, `tool ${tool.name}: ${where}`, text);
    }
    for (const [where, text] of stringLeaves(tool.annotations, "annotations")) {
      push(out, `tool ${tool.name}: ${where}`, text);
    }
  }
  for (const prompt of surface.prompts) {
    push(out, `prompt ${prompt.name}: description`, joinNonEmpty(prompt.name, prompt.description));
    for (const arg of prompt.arguments ?? []) {
      push(out, `prompt ${prompt.name}: argument ${arg.name}`, joinNonEmpty(arg.name, arg.description));
    }
  }
  for (const resource of surface.resources) {
    push(
      out,
      `resource ${resource.uri}: description`,
      joinNonEmpty(resource.name, resource.uri, resource.description),
    );
  }
  return out;
}

/** Gate 2: what the server answered to fuzz cases (our own case texts are not scanned). */
export function fuzzSegments(fuzz: FuzzReport): ScanSegment[] {
  const out: ScanSegment[] = [];
  for (const n of fuzz.notableResponses) {
    push(out, `fuzz ${n.caseId} (${n.tool}): notable response`, n.excerpt);
  }
  for (const c of fuzz.cases) {
    if (c.errorClass === "ok") continue;
    push(out, `fuzz ${c.caseId} (${c.tool}): error message`, c.errorMessage);
    push(out, `fuzz ${c.caseId} (${c.tool}): response`, c.responseExcerpt);
  }
  return out;
}

/** Gate 3: the server's answers to benign and active probes. */
export function probeSegments(probes: ProbeReport): ScanSegment[] {
  const out: ScanSegment[] = [];
  for (const b of probes.benignCalls) {
    push(out, `probe ${b.tool}: output`, b.outputExcerpt);
    for (const h of b.hits) push(out, `probe ${b.tool}: ${h.flag} hit`, h.excerpt);
  }
  for (const a of probes.activeProbes) {
    push(out, `active probe ${a.tool}.${a.parameter} (${a.kind}): evidence`, a.evidence);
  }
  for (const h of probes.serverInstructionsHits) {
    push(out, `server instructions: ${h.flag} hit`, h.excerpt);
  }
  for (const t of probes.toolDescriptionHits) {
    for (const h of t.hits) push(out, `tool ${t.tool}: ${h.flag} hit`, h.excerpt);
  }
  return out;
}

/**
 * Split text into ≤ maxChars pieces that overlap by `overlap` characters,
 * cutting at whitespace when one is near the limit. Never splits a UTF-16
 * surrogate pair.
 */
export function chunkText(text: string, maxChars = CHUNK_CHARS, overlap = CHUNK_OVERLAP): string[] {
  return chunkSpans(text, maxChars, overlap).map(([start, end]) => text.slice(start, end));
}

/** [start, end) offsets of chunkText's pieces. */
export function chunkSpans(text: string, maxChars = CHUNK_CHARS, overlap = CHUNK_OVERLAP): [number, number][] {
  if (maxChars <= 0 || overlap < 0 || overlap >= maxChars) {
    throw new Error(`invalid chunking: maxChars=${maxChars} overlap=${overlap}`);
  }
  if (text.length <= maxChars) {
    return [[0, text.length]];
  }
  const spans: [number, number][] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + maxChars, text.length);
    if (end < text.length) {
      // Prefer a whitespace cut in the last fifth of the window.
      const ws = lastWhitespace(text, start + Math.floor(maxChars * 0.8), end);
      if (ws > start) end = ws;
      if (isHighSurrogate(text.charCodeAt(end - 1))) end -= 1;
    }
    spans.push([start, end]);
    if (end >= text.length) break;
    let next = end - overlap;
    if (next <= start) next = end;
    if (isLowSurrogate(text.charCodeAt(next))) next += 1;
    start = next;
  }
  return spans;
}

/**
 * Segments → the requests to send: chunked, blank texts dropped, and each
 * distinct chunk sent once (fuzz error messages repeat a lot).
 */
export function scanUnits(segments: ScanSegment[], maxChars = CHUNK_CHARS, overlap = CHUNK_OVERLAP): ScanSegment[] {
  const seen = new Set<string>();
  const units: ScanSegment[] = [];
  for (const seg of segments) {
    const pieces = chunkText(seg.text, maxChars, overlap);
    pieces.forEach((piece, i) => {
      if (piece.trim() === "" || seen.has(piece)) return;
      seen.add(piece);
      units.push({ label: pieces.length > 1 ? `${seg.label} [part ${i + 1}/${pieces.length}]` : seg.label, text: piece });
    });
  }
  return units;
}

// ---------------------------------------------------------------------------

function push(out: ScanSegment[], label: string, text: string | undefined | null): void {
  if (typeof text === "string" && text.trim() !== "") {
    out.push({ label, text });
  }
}

function joinNonEmpty(...parts: (string | undefined)[]): string {
  return parts.filter((p): p is string => typeof p === "string" && p.trim() !== "").join(": ");
}

/**
 * Human-readable texts a JSON Schema carries: property names (they reach
 * the model too) and every string under description/title/default/examples/
 * enum/const, at any depth.
 */
function schemaTexts(schema: JsonSchema | undefined, path: string): [string, string][] {
  const out: [string, string][] = [];
  const walk = (node: unknown, where: string): void => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${where}[${i}]`));
      return;
    }
    if (node === null || typeof node !== "object") return;
    const obj = node as Record<string, unknown>;
    for (const key of ["description", "title"]) {
      if (typeof obj[key] === "string") out.push([`${where} ${key}`, obj[key] as string]);
    }
    for (const key of ["default", "examples", "enum", "const"]) {
      for (const [w, s] of stringLeaves(obj[key], `${where} ${key}`)) out.push([w, s]);
    }
    const props = obj["properties"];
    if (props && typeof props === "object" && !Array.isArray(props)) {
      const names = Object.keys(props);
      if (names.length > 0) out.push([`${where} property names`, names.join(" ")]);
      for (const [name, sub] of Object.entries(props)) walk(sub, `${where}.${name}`);
    }
    for (const key of ["items", "additionalProperties", "anyOf", "oneOf", "allOf", "not", "$defs", "definitions"]) {
      const sub = obj[key];
      if (sub === undefined) continue;
      if (key === "$defs" || key === "definitions") {
        if (sub && typeof sub === "object") {
          for (const [name, def] of Object.entries(sub as Record<string, unknown>)) walk(def, `${where} ${key}.${name}`);
        }
      } else {
        walk(sub, `${where} ${key}`);
      }
    }
  };
  walk(schema, path);
  return out;
}

function stringLeaves(node: unknown, where: string): [string, string][] {
  const out: [string, string][] = [];
  const walk = (n: unknown, w: string): void => {
    if (typeof n === "string") out.push([w, n]);
    else if (Array.isArray(n)) n.forEach((v, i) => walk(v, `${w}[${i}]`));
    else if (n && typeof n === "object") for (const [k, v] of Object.entries(n)) walk(v, `${w}.${k}`);
  };
  walk(node, where);
  return out;
}

function lastWhitespace(text: string, from: number, to: number): number {
  for (let i = to; i > from; i--) {
    if (/\s/.test(text[i - 1] ?? "")) return i;
  }
  return -1;
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/** Minimal verdict shape the gate needs (VigilVerdict satisfies it). */
export interface UnitVerdict {
  injectionDetected: boolean;
}

/**
 * Send the units one by one; stop at the first detection. Scanner errors
 * propagate unchanged so the caller's fail-closed policy applies.
 */
export async function scanUntilDetection<V extends UnitVerdict>(
  units: ScanSegment[],
  analyze: (unit: ScanSegment) => Promise<V>,
): Promise<{ scanned: number; hit?: { unit: ScanSegment; verdict: V } }> {
  let scanned = 0;
  for (const unit of units) {
    const verdict = await analyze(unit);
    scanned += 1;
    if (verdict.injectionDetected) {
      return { scanned, hit: { unit, verdict } };
    }
  }
  return { scanned };
}
