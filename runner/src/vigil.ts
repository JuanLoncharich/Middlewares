/**
 * Vigil-LLM client — inbound prompt-injection / jailbreak scanning.
 *
 * The evaluator POSTs every untrusted MCP payload (server instructions, tool
 * descriptions, fuzz/probe responses) to the Vigil REST API BEFORE the content
 * is formatted into any LLM prompt:
 *
 *   POST http://vigil-service:5000/analyze   {"prompt": "<untrusted payload>"}
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
  /** True when the payload is prompt injection / jailbreak / malicious. */
  injectionDetected: boolean;
  /** 0..1 confidence, when the server exposes one. */
  confidence?: number;
  /** Normalized names of scanners that fired. */
  triggeredScanners: string[];
  /** Raw response body, preserved for the evaluation report. */
  raw: unknown;
}

export interface VigilClientOptions {
  timeoutMs: number;
  /** Payload ceiling; longer payloads are truncated with a marker. */
  maxPayloadBytes: number;
  /** Network retry attempts (not re-scans). Default 3. */
  retries?: number;
}

const TRUNCATION_MARKER = "\n…[truncated by mcp-eval-runner for vigil scan]";
/** Backoff schedule between scan retries (ms). */
const RETRY_DELAYS_MS = [500, 1500, 4000];

export class VigilClient {
  private readonly url: string;
  private readonly meshFetch: MeshFetch;
  private readonly timeoutMs: number;
  private readonly maxPayloadBytes: number;
  private readonly retries: number;

  constructor(url: string, meshFetch: MeshFetch, options: VigilClientOptions) {
    if (!/^https?:\/\//.test(url)) {
      throw new Error(`VIGIL_URL must be an absolute http(s) URL, got "${url}"`);
    }
    this.url = url;
    this.meshFetch = meshFetch;
    this.timeoutMs = options.timeoutMs;
    this.maxPayloadBytes = options.maxPayloadBytes;
    this.retries = options.retries ?? 3;
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
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        await sleep(RETRY_DELAYS_MS[Math.min(attempt - 1, RETRY_DELAYS_MS.length - 1)] ?? 1000);
      }
      try {
        const res = await this.meshFetch(this.url, request);
        if (res.status === 0 || res.status >= 500) {
          lastError = `HTTP ${res.status} from vigil`;
          continue;
        }
        if (res.status === 404 || res.status === 405) {
          // Endpoint missing: the deployed vigil build does not serve /analyze.
          throw new VigilUnavailableError(source, `HTTP ${res.status} — /analyze not available at ${this.url}`);
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
        return this.interpret(parsed, source);
      } catch (err) {
        if (err instanceof VigilUnavailableError) {
          throw err;
        }
        lastError = errorMessage(err);
        log.warn("vigil scan attempt failed", { source, attempt: attempt + 1, error: lastError });
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
      return {
        injectionDetected: parsed["injection_detected"],
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      };
    }

    // 2) status-based shape ({status: "blocked"|"allowed", runs: {...}}).
    const status = typeof parsed["status"] === "string" ? parsed["status"].toLowerCase() : undefined;
    if (status !== undefined) {
      return {
        injectionDetected: status === "blocked" || status === "malicious" || status === "detected",
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      };
    }

    // 3) decision-based shape ({decision: {block: true, ...}} or a string).
    const decision = parsed["decision"];
    if (isRecord(decision) && typeof decision["block"] === "boolean") {
      return {
        injectionDetected: decision["block"],
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      };
    }
    if (typeof decision === "string") {
      const d = decision.toLowerCase();
      return {
        injectionDetected: d === "block" || d === "blocked" || d === "malicious" || d === "injection",
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      };
    }

    // 4) verdict string fallback ({verdict: "..."}).
    const verdict = parsed["verdict"];
    if (typeof verdict === "string") {
      const v = verdict.toLowerCase();
      return {
        injectionDetected: v.includes("inject") || v.includes("jailbreak") || v.includes("malicious"),
        confidence: readConfidence(parsed),
        triggeredScanners: readTriggeredScanners(parsed),
        raw: parsed,
      };
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
