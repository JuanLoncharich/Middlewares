/**
 * Vigil-LLM client — inbound prompt-injection / jailbreak scanning.
 *
 * The evaluator POSTs every untrusted MCP payload (server instructions, tool
 * descriptions, fuzz/probe responses) to the Vigil REST API BEFORE the content
 * is formatted into any LLM prompt:
 *
 *   POST <VIGIL_URL>/analyze/prompt   {"prompt": "<untrusted payload>"}
 *
 * Response parsing is written against the integration contract
 * (`injection_detected: boolean`) and degrades gracefully across the verdict
 * shapes actual vigil-llm releases emit:
 *
 *   { "injection_detected": true, ... }                       contract
 *   { "status": "blocked" | "allowed", "runs": {...} }        vigil < 0.12
 *   { "decision": { "block": true, "scores": {...} }, ... }   newer builds
 *
 * All calls go through the mesh fetch (NetBird SOCKS5 proxy) — never direct.
 * Scanning is best-effort resilient at the transport level (retries with
 * backoff) and absolute at the policy level: the CALLER decides strict
 * (fail-closed) vs monitor behaviour via env, and `analyze` never swallows a
 * detection.
 */

import { rootLogger, Logger } from "./logger.js";
import { VigilUnavailableError, errorMessage, isRecord } from "./types.js";
import type { MeshFetch, MeshRequestInit } from "./meshhttp.js";

const log: Logger = rootLogger.child("vigil");

export interface VigilVerdict {
  /** clean / warn / abort — see combineScannerResults. */
  level: VigilLevel;
  /** level === "abort": the payload is treated as malicious. */
  injectionDetected: boolean;
  /** Scanner matches that counted (upstream ResponseModel shape only). */
  hits: VigilScannerHit[];
  /** 0..1 confidence, when the server exposes one. */
  confidence?: number;
  /** Normalized names of scanners that fired. */
  triggeredScanners: string[];
  /** Raw response body, preserved for the evaluation report. */
  raw: unknown;
  /** Endpoint that produced this verdict (GPU scanner or the CPU fallback). */
  endpoint?: string;
}

export interface VigilClientOptions {
  timeoutMs: number;
  /** Payload ceiling; longer payloads are truncated with a marker. */
  maxPayloadBytes: number;
  /** Network retry attempts (not re-scans). Default 3. */
  retries?: number;
  /**
   * Optional GPU Vigil (same image and config as `url`, CUDA build) tried
   * first: same verdicts, faster. When it is unreachable (the GPU node is
   * detached or scaled to zero) the scan falls back to `url`.
   * Empty/undefined disables it.
   */
  preferredUrl?: string;
  /**
   * Transformer score at or above which a transformer match counts, used
   * when Vigil's response does not carry the threshold it was configured
   * with. Default 0.98 (manifests/vigil-deployment.yaml).
   */
  transformerThreshold?: number;
}

/** One scanner that matched, as the gate reports it. */
export interface VigilScannerHit {
  scanner: string;
  /** Transformer: INJECTION score; vectordb: best (smallest) distance. */
  score?: number;
  /** YARA: matched rule names. */
  detail?: string;
}

/**
 * clean: nothing counted. warn: something matched, but not enough to call
 * the text malicious. abort: the strict/Malicious path.
 */
export type VigilLevel = "clean" | "warn" | "abort";

export const DEFAULT_TRANSFORMER_THRESHOLD = 0.98;

const TRUNCATION_MARKER = "\n…[truncated by mcp-eval-runner for vigil scan]";
/** Backoff schedule between scan retries (ms). */
const RETRY_DELAYS_MS = [500, 1500, 4000];

export class VigilClient {
  private readonly url: string;
  private readonly meshFetch: MeshFetch;
  private readonly timeoutMs: number;
  private readonly maxPayloadBytes: number;
  private readonly retries: number;
  private readonly preferredUrl: string | undefined;
  private readonly transformerThreshold: number;

  constructor(url: string, meshFetch: MeshFetch, options: VigilClientOptions) {
    if (!/^https?:\/\//.test(url)) {
      throw new Error(`VIGIL_URL must be an absolute http(s) URL, got "${url}"`);
    }
    this.url = url;
    this.meshFetch = meshFetch;
    this.timeoutMs = options.timeoutMs;
    this.maxPayloadBytes = options.maxPayloadBytes;
    this.retries = options.retries ?? 3;
    const preferred = options.preferredUrl?.trim();
    if (preferred && !/^https?:\/\//.test(preferred)) {
      throw new Error(`VIGIL_GPU_URL must be an absolute http(s) URL, got "${preferred}"`);
    }
    this.preferredUrl = preferred || undefined;
    this.transformerThreshold = options.transformerThreshold ?? DEFAULT_TRANSFORMER_THRESHOLD;
  }

  get endpoint(): string {
    return this.url;
  }

  /**
   * Scan one untrusted payload. Resolves with the verdict — throws
   * VigilUnavailableError only when the SERVICE is unusable (network, 5xx,
   * unparseable answer); a "clean" verdict is a normal resolution.
   */
  async analyze(payload: string, source: string): Promise<VigilVerdict> {
    const body = this.truncate(payload);
    if (this.preferredUrl !== undefined) {
      try {
        // One retry only: a detached GPU node must cost a moment, not minutes.
        return await this.analyzeAt(this.preferredUrl, body, source, 1);
      } catch (err) {
        if (!(err instanceof VigilUnavailableError)) {
          throw err;
        }
        log.warn("GPU vigil unavailable — falling back to the CPU scanner", {
          source,
          gpu: this.preferredUrl,
          error: errorMessage(err),
        });
      }
    }
    return this.analyzeAt(this.url, body, source, this.retries);
  }

  private async analyzeAt(url: string, body: string, source: string, retries: number): Promise<VigilVerdict> {
    const request: MeshRequestInit = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "accept": "application/json",
        "user-agent": "mcp-eval-runner",
      },
      body: JSON.stringify({ prompt: body }),
      timeoutMs: this.timeoutMs,
    };

    let lastError = "";
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (attempt > 0) {
        await sleep(RETRY_DELAYS_MS[Math.min(attempt - 1, RETRY_DELAYS_MS.length - 1)] ?? 1000);
      }
      try {
        const res = await this.meshFetch(url, request);
        if (res.status === 0 || res.status >= 500) {
          lastError = `HTTP ${res.status} from vigil`;
          continue;
        }
        if (res.status === 404 || res.status === 405) {
          // Endpoint missing: the deployed vigil build does not serve /analyze.
          throw new VigilUnavailableError(source, `HTTP ${res.status} — /analyze not available at ${url}`);
        }
        if (res.status >= 400) {
          // 4xx (other than routing misses) is a contract problem worth
          // surfacing immediately — retries will not fix a bad request.
          throw new VigilUnavailableError(source, `HTTP ${res.status}: ${res.text().slice(0, 300)}`);
        }
        let parsed: unknown;
        try {
          parsed = res.json();
        } catch (err) {
          throw new VigilUnavailableError(source, `response is not JSON: ${errorMessage(err)} — body: ${res.text().slice(0, 200)}`);
        }
        const verdict = this.interpret(parsed, source);
        verdict.endpoint = url;
        return verdict;
      } catch (err) {
        if (err instanceof VigilUnavailableError) {
          throw err;
        }
        lastError = errorMessage(err);
        log.warn("vigil scan attempt failed", { source, url, attempt: attempt + 1, error: lastError });
      }
    }
    throw new VigilUnavailableError(source, lastError || "no response");
  }

  /**
   * Map any known vigil-llm verdict shape onto the contract. Unknown shapes
   * are treated as a scanner outage (caller decides fail-open vs fail-closed)
   * — never silently as "clean".
   */
  private interpret(parsed: unknown, source: string): VigilVerdict {
    if (!isRecord(parsed)) {
      throw new VigilUnavailableError(source, "response JSON is not an object");
    }

    // 1) Integration contract field.
    if (typeof parsed["injection_detected"] === "boolean") {
      return legacy({
        injectionDetected: parsed["injection_detected"],
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      });
    }

    // 2) Per-scanner matches shape — upstream vigil-llm ResponseModel
    // (pinned f2b4c13): status is always "success"/"partial_success"/"failed"
    // and detections are signalled by results: {"scanner:yara": {"matches": [...]}}.
    // Checked BEFORE the status shape below, whose "success" would otherwise
    // read as clean.
    const scanResults = parsed["results"];
    if (isRecord(scanResults)) {
      const combined = combineScannerResults(scanResults, this.transformerThreshold);
      return {
        level: combined.level,
        injectionDetected: combined.level === "abort",
        hits: combined.hits,
        confidence: readConfidence(parsed),
        triggeredScanners: combined.hits.map((h) => h.scanner),
        raw: parsed,
      };
    }

    // 3) status-based shape ({status: "blocked"|"allowed", runs: {...}}).
    const status = typeof parsed["status"] === "string" ? parsed["status"].toLowerCase() : undefined;
    if (status !== undefined) {
      return legacy({
        injectionDetected: status === "blocked" || status === "malicious" || status === "detected",
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      });
    }

    // 4) decision-based shape ({decision: {block: true, ...}} or a string).
    const decision = parsed["decision"];
    if (isRecord(decision) && typeof decision["block"] === "boolean") {
      return legacy({
        injectionDetected: decision["block"],
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      });
    }
    if (typeof decision === "string") {
      const d = decision.toLowerCase();
      return legacy({
        injectionDetected: d === "block" || d === "blocked" || d === "malicious" || d === "injection",
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      });
    }

    // 5) verdict string fallback ({verdict: "..."}).
    const verdict = parsed["verdict"];
    if (typeof verdict === "string") {
      const v = verdict.toLowerCase();
      return legacy({
        injectionDetected: v.includes("inject") || v.includes("jailbreak") || v.includes("malicious"),
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      });
    }

    throw new VigilUnavailableError(source, `unrecognized verdict shape: ${JSON.stringify(parsed).slice(0, 300)}`);
  }

  private truncate(payload: string): string {
    const bytes = Buffer.byteLength(payload, "utf8");
    if (bytes <= this.maxPayloadBytes) {
      return payload;
    }
    log.debug("payload truncated for vigil scan", { bytes, cap: this.maxPayloadBytes });
    return Buffer.from(payload, "utf8").subarray(0, this.maxPayloadBytes).toString("utf8") + TRUNCATION_MARKER;
  }

}

/**
 * The gate's rule for upstream's per-scanner results (decided by Juan,
 * 2026-10-14, after measuring per-text scanning on 684 benign texts: the
 * transformer flags 2.3% at >= 0.98 — e.g. "Reverse the characters of the
 * provided text." at 0.999 — and upstream YARA 3.8%, mostly docs that quote
 * attacks; both together, 0.3%):
 *
 *  - a transformer match counts only at score >= its threshold (upstream
 *    also reports INJECTION labels below it, "for manual review");
 *  - transformer AND (YARA or vectordb) on the same text => abort;
 *  - any scanner on its own => warn (recorded, shown to the auditor).
 */
export function combineScannerResults(
  results: Record<string, unknown>,
  defaultThreshold = DEFAULT_TRANSFORMER_THRESHOLD,
): { level: VigilLevel; hits: VigilScannerHit[] } {
  const hits: VigilScannerHit[] = [];
  let transformer = false;
  let corroborating = false;
  for (const [name, r] of Object.entries(results)) {
    if (name === "scanner:sentiment" || !isRecord(r) || !Array.isArray(r["matches"])) continue;
    const matches = r["matches"].filter(isRecord);
    if (name === "scanner:transformer") {
      let best: number | undefined;
      for (const m of matches) {
        const score = typeof m["score"] === "number" ? m["score"] : undefined;
        const threshold = typeof m["threshold"] === "number" ? m["threshold"] : defaultThreshold;
        const injection = m["label"] === undefined || m["label"] === "INJECTION";
        if (injection && score !== undefined && score >= threshold) {
          best = best === undefined ? score : Math.max(best, score);
        }
      }
      if (best !== undefined) {
        transformer = true;
        hits.push({ scanner: name, score: best });
      }
      continue;
    }
    if (matches.length === 0) continue;
    if (name === "scanner:yara") {
      corroborating = true;
      const rules = matches.map((m) => m["rule_name"]).filter((x): x is string => typeof x === "string");
      hits.push({ scanner: name, detail: rules.join(", ") });
      // Seam: a YARA-only abort (e.g. for a curated set of high-confidence
      // rules) would be decided here. Deliberately not enabled: YARA on its
      // own only warns until that is settled.
    } else if (name === "scanner:vectordb") {
      corroborating = true;
      const distances = matches.map((m) => m["distance"]).filter((x): x is number => typeof x === "number");
      hits.push({ scanner: name, ...(distances.length > 0 ? { score: Math.min(...distances) } : {}) });
    } else {
      // A scanner this rule does not know: visible, never decisive.
      hits.push({ scanner: name });
    }
  }
  const level: VigilLevel = transformer && corroborating ? "abort" : hits.length > 0 ? "warn" : "clean";
  return { level, hits };
}

/** Verdict shapes other than upstream's per-scanner results: detected = abort. */
function legacy(v: Omit<VigilVerdict, "level" | "hits">): VigilVerdict {
  return { ...v, level: v.injectionDetected ? "abort" : "clean", hits: [] };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readConfidence(obj: Record<string, unknown>): number | undefined {
  for (const key of ["confidence", "score", "max_score"]) {
    const v = obj[key];
    if (typeof v === "number" && Number.isFinite(v)) {
      return v > 1 ? v / 100 : v;
    }
  }
  // Max score across per-scanner runs, when present.
  const runs = obj["runs"];
  if (isRecord(runs)) {
    let max: number | undefined;
    for (const value of Object.values(runs)) {
      if (isRecord(value) && typeof value["score"] === "number" && Number.isFinite(value["score"])) {
        const s = value["score"];
        max = max === undefined ? s : Math.max(max, s);
      }
    }
    return max;
  }
  return undefined;
}

function readTriggeredScanners(obj: Record<string, unknown>): string[] {
  const fired: string[] = [];
  const runs = obj["runs"];
  if (isRecord(runs)) {
    for (const [name, value] of Object.entries(runs)) {
      if (!isRecord(value)) continue;
      const score = value["score"];
      const flagged =
        value["is_injection"] === true ||
        value["positive"] === true ||
        value["blocked"] === true ||
        (typeof score === "number" && Number.isFinite(score) && score >= 0.8);
      if (flagged) {
        fired.push(name);
      }
    }
  }
  const scanners = obj["scanners"];
  if (fired.length === 0 && Array.isArray(scanners)) {
    for (const item of scanners) {
      if (typeof item === "string") fired.push(item);
    }
  }
  return fired;
}

/** Short human excerpt of an offending payload for logs/findings. */
export function excerptOf(payload: string, max = 200): string {
  const flat = payload.replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : `${flat.slice(0, max)}…`;
}
