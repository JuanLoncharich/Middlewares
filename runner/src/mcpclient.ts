/**
 * Minimal JSON-RPC 2.0 / MCP client with two transports:
 *
 *  - StdioFifoTransport: newline-delimited JSON over the /ipc/stdin and
 *    /ipc/stdout FIFOs shared with the sandboxed target container. Detects
 *    EOF / EPIPE as a target crash and reconnects.
 *  - SseTransport: legacy HTTP+SSE (GET /sse -> `endpoint` event -> POST) with
 *    a Streamable-HTTP fallback (POST /mcp with SSE or JSON responses), always
 *    against 127.0.0.1 inside the pod network namespace.
 *
 * The client records latency, hangs (per-request timeouts), crashes, malformed
 * frames and unsolicited server->client requests for the telemetry report.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { Logger, rootLogger } from "./logger.js";
import {
  JsonRpcError,
  JsonRpcId,
  JsonRpcMessage,
  JsonRpcRequest,
  LatencyStats,
  MalformedFrameError,
  McpInitializeResult,
  McpPromptDefinition,
  McpResourceDefinition,
  McpToolCallResult,
  McpToolDefinition,
  RpcOutcome,
  TargetCrashError,
  TargetUnavailableError,
  errorMessage,
  isRecord,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

export class LatencyRecorder {
  private readonly samples: number[] = [];

  record(ms: number): void {
    if (Number.isFinite(ms) && ms >= 0) {
      this.samples.push(ms);
    }
  }

  stats(): LatencyStats {
    if (this.samples.length === 0) {
      return { count: 0, avgMs: 0, p95Ms: 0, maxMs: 0, minMs: 0 };
    }
    const sorted = [...this.samples].sort((a, b) => a - b);
    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
    const p95 = sorted[p95Index] ?? 0;
    const max = sorted[sorted.length - 1] ?? 0;
    const min = sorted[0] ?? 0;
    return {
      count: sorted.length,
      avgMs: Math.round((sum / sorted.length) * 100) / 100,
      p95Ms: p95,
      maxMs: max,
      minMs: min,
    };
  }
}

// ---------------------------------------------------------------------------
// Transport interface
// ---------------------------------------------------------------------------

export type FrameCallback = (frame: string) => void;
export type CloseCallback = (reason: string) => void;

export interface McpTransport {
  readonly kind: "stdio" | "sse";
  start(): Promise<void>;
  send(frame: string): Promise<void>;
  onFrame(cb: FrameCallback): void;
  onClose(cb: CloseCallback): void;
  close(): Promise<void>;
  /** Number of target crashes observed by this transport. */
  crashCount(): number;
  /** Re-establish the connection after a crash. */
  reconnect(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Stdio FIFO transport
// ---------------------------------------------------------------------------

export interface StdioFifoOptions {
  ipcDir: string;
  openTimeoutMs?: number;
  reconnectDelayMs?: number;
}

export class StdioFifoTransport implements McpTransport {
  public readonly kind = "stdio" as const;
  private readonly ipcDir: string;
  private readonly stdinPath: string;
  private readonly stdoutPath: string;
  private readonly crashesPath: string;
  private readonly openTimeoutMs: number;
  private readonly reconnectDelayMs: number;
  private readonly log: Logger;
  private frameCb: FrameCallback | null = null;
  private closeCb: CloseCallback | null = null;
  private writeHandle: fs.promises.FileHandle | null = null;
  private readHandle: fs.promises.FileHandle | null = null;
  private readStream: fs.ReadStream | null = null;
  private buffer = "";
  private closed = false;
  private connected = false;
  private crashes = 0;
  private generation = 0;

  constructor(options: StdioFifoOptions) {
    this.ipcDir = options.ipcDir;
    this.stdinPath = path.join(options.ipcDir, "stdin");
    this.stdoutPath = path.join(options.ipcDir, "stdout");
    this.crashesPath = path.join(options.ipcDir, "crashes.jsonl");
    this.openTimeoutMs = options.openTimeoutMs ?? 60000;
    this.reconnectDelayMs = options.reconnectDelayMs ?? 1000;
    this.log = rootLogger.child("stdio");
  }

  onFrame(cb: FrameCallback): void {
    this.frameCb = cb;
  }

  onClose(cb: CloseCallback): void {
    this.closeCb = cb;
  }

  crashCount(): number {
    return Math.max(this.crashes, this.readCrashFile());
  }

  async start(): Promise<void> {
    if (!fs.existsSync(this.stdinPath) || !fs.existsSync(this.stdoutPath)) {
      throw new TargetUnavailableError(`FIFOs not present in ${this.ipcDir} (expected stdin and stdout)`);
    }
    await this.open();
  }

  async reconnect(): Promise<void> {
    await this.teardownHandles();
    await sleep(this.reconnectDelayMs);
    await this.open();
  }

  async send(frame: string): Promise<void> {
    if (this.closed) {
      throw new TargetUnavailableError("transport closed");
    }
    const handle = this.writeHandle;
    if (!handle || !this.connected) {
      throw new TargetUnavailableError("stdio transport is not connected");
    }
    const payload = frame.endsWith("\n") ? frame : frame + "\n";
    try {
      await handle.write(payload, null, "utf8");
    } catch (err) {
      const message = errorMessage(err);
      if (message.includes("EPIPE") || message.includes("EBADF")) {
        this.handleCrash(`write failed: ${message}`);
        throw new TargetCrashError(message);
      }
      throw new TargetUnavailableError(`write failed: ${message}`);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    await this.teardownHandles();
  }

  private async open(): Promise<void> {
    const gen = ++this.generation;
    this.buffer = "";
    // Both opens block until the peer side is opened by the target container:
    // the target's shell opens stdin (read) first, then stdout (write).
    // Running them concurrently ensures neither side deadlocks.
    let handles: [fs.promises.FileHandle, fs.promises.FileHandle];
    try {
      handles = await withTimeout(
        Promise.all([
          fs.promises.open(this.stdinPath, fs.constants.O_WRONLY),
          fs.promises.open(this.stdoutPath, fs.constants.O_RDONLY),
        ]),
        this.openTimeoutMs,
        "opening IPC FIFOs",
      );
    } catch (err) {
      throw new TargetUnavailableError(`could not open IPC FIFOs: ${errorMessage(err)}`);
    }
    if (gen !== this.generation || this.closed) {
      await Promise.allSettled([handles[0].close(), handles[1].close()]);
      return;
    }
    this.writeHandle = handles[0];
    this.readHandle = handles[1];
    const stream = handles[1].createReadStream({ encoding: "utf8", autoClose: false, highWaterMark: 64 * 1024 });
    this.readStream = stream;
    stream.on("data", (chunk: string | Buffer) => {
      if (gen !== this.generation) {
        return;
      }
      this.buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      this.drainBuffer();
    });
    stream.on("end", () => {
      if (gen !== this.generation) {
        return;
      }
      this.handleCrash("EOF on target stdout");
    });
    stream.on("error", (err: Error) => {
      if (gen !== this.generation) {
        return;
      }
      this.handleCrash(`read error: ${err.message}`);
    });
    this.connected = true;
    this.log.info("stdio transport connected", { generation: gen });
  }

  private drainBuffer(): void {
    let newlineIndex = this.buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const line = this.buffer.slice(0, newlineIndex).replace(/\r$/, "");
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (line.trim().length > 0 && this.frameCb) {
        this.frameCb(line);
      }
      newlineIndex = this.buffer.indexOf("\n");
    }
    if (this.buffer.length > 8 * 1024 * 1024) {
      // Defensive: a target that never sends a newline cannot exhaust memory.
      const dropped = this.buffer;
      this.buffer = "";
      if (this.frameCb) {
        this.frameCb(dropped);
      }
    }
  }

  private handleCrash(reason: string): void {
    if (!this.connected) {
      return;
    }
    this.connected = false;
    this.crashes += 1;
    this.log.warn("target connection lost", { reason, crashes: this.crashes });
    if (this.closeCb) {
      this.closeCb(reason);
    }
  }

  private async teardownHandles(): Promise<void> {
    this.connected = false;
    this.generation += 1;
    const stream = this.readStream;
    this.readStream = null;
    if (stream) {
      stream.removeAllListeners();
      stream.destroy();
    }
    const closers: Promise<void>[] = [];
    if (this.writeHandle) {
      closers.push(this.writeHandle.close().catch(() => undefined));
      this.writeHandle = null;
    }
    if (this.readHandle) {
      closers.push(this.readHandle.close().catch(() => undefined));
      this.readHandle = null;
    }
    await Promise.all(closers);
  }

  private readCrashFile(): number {
    try {
      if (!fs.existsSync(this.crashesPath)) {
        return 0;
      }
      const content = fs.readFileSync(this.crashesPath, "utf8");
      return content.split("\n").filter((l) => l.trim().length > 0).length;
    } catch {
      return 0;
    }
  }
}

// ---------------------------------------------------------------------------
// SSE / Streamable HTTP transport
// ---------------------------------------------------------------------------

export interface SseOptions {
  host?: string;
  port: number;
  ssePath?: string;
  streamablePath?: string;
  connectTimeoutMs?: number;
  reconnectDelayMs?: number;
}

interface SseEvent {
  event: string;
  data: string;
}

class SseParser {
  private buffer = "";

  push(chunk: string): SseEvent[] {
    this.buffer += chunk;
    const events: SseEvent[] = [];
    let sepIndex = this.findSeparator();
    while (sepIndex.index >= 0) {
      const block = this.buffer.slice(0, sepIndex.index);
      this.buffer = this.buffer.slice(sepIndex.index + sepIndex.length);
      const parsed = this.parseBlock(block);
      if (parsed) {
        events.push(parsed);
      }
      sepIndex = this.findSeparator();
    }
    return events;
  }

  private findSeparator(): { index: number; length: number } {
    const a = this.buffer.indexOf("\n\n");
    const b = this.buffer.indexOf("\r\n\r\n");
    if (a < 0 && b < 0) {
      return { index: -1, length: 0 };
    }
    if (a >= 0 && (b < 0 || a < b)) {
      return { index: a, length: 2 };
    }
    return { index: b, length: 4 };
  }

  private parseBlock(block: string): SseEvent | null {
    let event = "message";
    const dataLines: string[] = [];
    for (const rawLine of block.split(/\r?\n/)) {
      if (rawLine.startsWith(":") || rawLine.length === 0) {
        continue;
      }
      const colon = rawLine.indexOf(":");
      const field = colon >= 0 ? rawLine.slice(0, colon) : rawLine;
      let value = colon >= 0 ? rawLine.slice(colon + 1) : "";
      if (value.startsWith(" ")) {
        value = value.slice(1);
      }
      if (field === "event") {
        event = value;
      } else if (field === "data") {
        dataLines.push(value);
      }
    }
    if (dataLines.length === 0) {
      return null;
    }
    return { event, data: dataLines.join("\n") };
  }
}

export class SseTransport implements McpTransport {
  public readonly kind = "sse" as const;
  private readonly baseUrl: string;
  private readonly ssePath: string;
  private readonly streamablePath: string;
  private readonly connectTimeoutMs: number;
  private readonly reconnectDelayMs: number;
  private readonly log: Logger;
  private frameCb: FrameCallback | null = null;
  private closeCb: CloseCallback | null = null;
  private mode: "sse" | "streamable" = "sse";
  private postUrl: string | null = null;
  private sessionId: string | null = null;
  private abort: AbortController | null = null;
  private connected = false;
  private closed = false;
  private crashes = 0;

  constructor(options: SseOptions) {
    const host = options.host ?? "127.0.0.1";
    this.baseUrl = `http://${host}:${options.port}`;
    this.ssePath = options.ssePath ?? "/sse";
    this.streamablePath = options.streamablePath ?? "/mcp";
    this.connectTimeoutMs = options.connectTimeoutMs ?? 60000;
    this.reconnectDelayMs = options.reconnectDelayMs ?? 1000;
    this.log = rootLogger.child("sse");
  }

  onFrame(cb: FrameCallback): void {
    this.frameCb = cb;
  }

  onClose(cb: CloseCallback): void {
    this.closeCb = cb;
  }

  crashCount(): number {
    return this.crashes;
  }

  async start(): Promise<void> {
    const deadline = Date.now() + this.connectTimeoutMs;
    let lastError = "";
    while (Date.now() < deadline) {
      if (this.closed) {
        throw new TargetUnavailableError("transport closed");
      }
      try {
        await this.connectSse();
        return;
      } catch (err) {
        lastError = errorMessage(err);
        if (lastError.includes("HTTP 404") || lastError.includes("HTTP 405")) {
          // Server does not expose legacy SSE; use Streamable HTTP.
          this.mode = "streamable";
          this.postUrl = this.baseUrl + this.streamablePath;
          this.connected = true;
          this.log.info("using streamable-http transport", { url: this.postUrl });
          return;
        }
      }
      await sleep(1000);
    }
    throw new TargetUnavailableError(`could not connect to ${this.baseUrl}${this.ssePath}: ${lastError}`);
  }

  async reconnect(): Promise<void> {
    this.abort?.abort();
    this.abort = null;
    this.connected = false;
    this.postUrl = this.mode === "streamable" ? this.baseUrl + this.streamablePath : null;
    this.sessionId = null;
    await sleep(this.reconnectDelayMs);
    await this.start();
  }

  async send(frame: string): Promise<void> {
    if (this.closed) {
      throw new TargetUnavailableError("transport closed");
    }
    if (!this.connected || !this.postUrl) {
      throw new TargetUnavailableError("sse transport is not connected");
    }
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (this.sessionId) {
      headers["Mcp-Session-Id"] = this.sessionId;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    let response: Response;
    try {
      response = await fetch(this.postUrl, { method: "POST", headers, body: frame, signal: controller.signal });
    } catch (err) {
      clearTimeout(timer);
      const message = errorMessage(err);
      if (message.includes("ECONNREFUSED") || message.includes("ECONNRESET") || message.includes("fetch failed")) {
        this.handleCrash(`POST failed: ${message}`);
        throw new TargetCrashError(message);
      }
      throw new TargetUnavailableError(`POST failed: ${message}`);
    }
    const session = response.headers.get("mcp-session-id");
    if (session) {
      this.sessionId = session;
    }
    const contentType = response.headers.get("content-type") ?? "";
    try {
      if (response.status === 202 || response.status === 204) {
        return;
      }
      if (contentType.includes("text/event-stream") && response.body) {
        await this.consumeStream(response.body, false);
        return;
      }
      const text = await response.text();
      if (response.status >= 400) {
        // Deliver as a raw frame so the client can classify it as malformed/HTTP error.
        if (this.frameCb && text.trim().length > 0) {
          this.frameCb(text);
        } else if (this.frameCb) {
          this.frameCb(`{"http_status":${response.status}}`);
        }
        return;
      }
      if (text.trim().length > 0 && this.frameCb) {
        this.frameCb(text);
      }
    } finally {
      clearTimeout(timer);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    this.connected = false;
    this.abort?.abort();
    this.abort = null;
  }

  private async connectSse(): Promise<void> {
    const controller = new AbortController();
    this.abort = controller;
    let response: Response;
    try {
      response = await fetch(this.baseUrl + this.ssePath, {
        method: "GET",
        headers: { Accept: "text/event-stream" },
        signal: controller.signal,
      });
    } catch (err) {
      throw new Error(`GET ${this.ssePath} failed: ${errorMessage(err)}`);
    }
    if (!response.ok || !response.body) {
      throw new Error(`GET ${this.ssePath} returned HTTP ${response.status}`);
    }
    const endpointPromise = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no endpoint event within 15s")), 15000);
      this.pendingEndpoint = (url: string) => {
        clearTimeout(timer);
        resolve(url);
      };
      this.pendingEndpointReject = (err: Error) => {
        clearTimeout(timer);
        reject(err);
      };
    });
    void this.consumeStream(response.body, true).catch((err: unknown) => {
      if (this.pendingEndpointReject) {
        this.pendingEndpointReject(new Error(errorMessage(err)));
      }
    });
    const endpoint = await endpointPromise;
    this.postUrl = new URL(endpoint, this.baseUrl).toString();
    this.mode = "sse";
    this.connected = true;
    this.log.info("sse transport connected", { postUrl: this.postUrl });
  }

  private pendingEndpoint: ((url: string) => void) | null = null;
  private pendingEndpointReject: ((err: Error) => void) | null = null;

  private async consumeStream(body: ReadableStream<Uint8Array>, isPrimary: boolean): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    const parser = new SseParser();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        const events = parser.push(decoder.decode(value, { stream: true }));
        for (const evt of events) {
          if (evt.event === "endpoint") {
            if (this.pendingEndpoint) {
              this.pendingEndpoint(evt.data.trim());
              this.pendingEndpoint = null;
              this.pendingEndpointReject = null;
            }
            continue;
          }
          if (this.frameCb) {
            this.frameCb(evt.data);
          }
        }
      }
      if (isPrimary) {
        this.handleCrash("SSE stream ended");
      }
    } catch (err) {
      if (isPrimary && !this.closed) {
        this.handleCrash(`SSE stream error: ${errorMessage(err)}`);
      }
      if (!isPrimary) {
        throw err;
      }
    }
  }

  private handleCrash(reason: string): void {
    if (!this.connected) {
      return;
    }
    this.connected = false;
    this.crashes += 1;
    this.log.warn("target connection lost", { reason, crashes: this.crashes });
    if (this.closeCb) {
      this.closeCb(reason);
    }
  }
}

// ---------------------------------------------------------------------------
// MCP client
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (outcome: RpcOutcome) => void;
  timer: NodeJS.Timeout;
  startedAt: number;
  method: string;
}

export interface McpClientOptions {
  transport: McpTransport;
  defaultTimeoutMs?: number;
  clientName?: string;
  clientVersion?: string;
}

export interface UnsolicitedRequestRecord {
  method: string;
  count: number;
}

const PROTOCOL_VERSIONS = ["2025-06-18", "2024-11-05"] as const;

export class McpClient {
  private readonly transport: McpTransport;
  private readonly defaultTimeoutMs: number;
  private readonly clientName: string;
  private readonly clientVersion: string;
  private readonly log: Logger;
  private readonly pending = new Map<string, PendingRequest>();
  private readonly unsolicited = new Map<string, number>();
  private nextId = 1;
  private notificationsCount = 0;
  private malformedCount = 0;
  private lastMalformed: MalformedFrameError | null = null;
  private crashEvents = 0;
  private initialized: McpInitializeResult | null = null;
  private negotiatedVersion = "";
  public readonly latency = new LatencyRecorder();

  constructor(options: McpClientOptions) {
    this.transport = options.transport;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 15000;
    this.clientName = options.clientName ?? "mcp-eval-runner";
    this.clientVersion = options.clientVersion ?? "0.1.0";
    this.log = rootLogger.child("mcp");
    this.transport.onFrame((frame) => this.handleFrame(frame));
    this.transport.onClose((reason) => this.handleClose(reason));
  }

  get transportKind(): "stdio" | "sse" {
    return this.transport.kind;
  }

  get initializeResult(): McpInitializeResult | null {
    return this.initialized;
  }

  get protocolVersion(): string {
    return this.negotiatedVersion;
  }

  get malformedFrames(): number {
    return this.malformedCount;
  }

  get notifications(): number {
    return this.notificationsCount;
  }

  get crashes(): number {
    return Math.max(this.crashEvents, this.transport.crashCount());
  }

  unsolicitedRequests(): UnsolicitedRequestRecord[] {
    return [...this.unsolicited.entries()].map(([method, count]) => ({ method, count }));
  }

  totalUnsolicited(): number {
    let total = 0;
    for (const count of this.unsolicited.values()) {
      total += count;
    }
    return total;
  }

  async start(): Promise<void> {
    await this.transport.start();
  }

  async close(): Promise<void> {
    for (const [id, req] of this.pending.entries()) {
      clearTimeout(req.timer);
      req.resolve({ ok: false, hang: false, crashed: false, latencyMs: 0, transportError: "client closed" });
      this.pending.delete(id);
    }
    await this.transport.close();
  }

  /** Waits for the target to accept an initialize handshake, retrying up to `maxWaitMs`. */
  async initializeWithRetry(maxWaitMs: number): Promise<McpInitializeResult> {
    const deadline = Date.now() + maxWaitMs;
    let lastError = "";
    let attempt = 0;
    while (Date.now() < deadline) {
      attempt += 1;
      try {
        return await this.initialize();
      } catch (err) {
        lastError = errorMessage(err);
        this.log.warn("initialize attempt failed", { attempt, error: lastError });
        if (err instanceof TargetCrashError) {
          try {
            await this.transport.reconnect();
          } catch (reconnectErr) {
            lastError = errorMessage(reconnectErr);
          }
        } else {
          await sleep(1000);
        }
      }
    }
    throw new TargetUnavailableError(`initialize did not succeed within ${maxWaitMs}ms: ${lastError}`);
  }

  async initialize(): Promise<McpInitializeResult> {
    let lastOutcome: RpcOutcome | null = null;
    for (const version of PROTOCOL_VERSIONS) {
      const outcome = await this.request(
        "initialize",
        {
          protocolVersion: version,
          capabilities: { roots: { listChanged: false }, sampling: {}, elicitation: {} },
          clientInfo: { name: this.clientName, version: this.clientVersion },
        },
        this.defaultTimeoutMs,
      );
      lastOutcome = outcome;
      if (outcome.crashed) {
        throw new TargetCrashError(outcome.transportError ?? "target crashed during initialize");
      }
      if (outcome.hang) {
        throw new TargetUnavailableError("initialize request hung");
      }
      if (outcome.ok && isRecord(outcome.result)) {
        const result = outcome.result;
        const protocolVersion = typeof result["protocolVersion"] === "string" ? result["protocolVersion"] : version;
        const capabilities = isRecord(result["capabilities"]) ? result["capabilities"] : {};
        const serverInfoRaw = isRecord(result["serverInfo"]) ? result["serverInfo"] : {};
        const init: McpInitializeResult = {
          protocolVersion,
          capabilities,
          serverInfo: {
            name: typeof serverInfoRaw["name"] === "string" ? serverInfoRaw["name"] : undefined,
            version: typeof serverInfoRaw["version"] === "string" ? serverInfoRaw["version"] : undefined,
          },
          instructions: typeof result["instructions"] === "string" ? result["instructions"] : undefined,
        };
        this.initialized = init;
        this.negotiatedVersion = protocolVersion;
        await this.notify("notifications/initialized", {});
        return init;
      }
      // If the server rejected the version explicitly, try the next one.
      if (outcome.error && /protocol|version/i.test(outcome.error.message)) {
        continue;
      }
      break;
    }
    const detail = lastOutcome?.error
      ? `${lastOutcome.error.code} ${lastOutcome.error.message}`
      : lastOutcome?.transportError ?? "unexpected initialize result";
    throw new TargetUnavailableError(`initialize rejected: ${detail}`);
  }

  async listTools(): Promise<McpToolDefinition[]> {
    const items = await this.paginate("tools/list", "tools");
    const tools: McpToolDefinition[] = [];
    for (const item of items) {
      if (isRecord(item) && typeof item["name"] === "string") {
        tools.push({
          name: item["name"],
          description: typeof item["description"] === "string" ? item["description"] : undefined,
          inputSchema: isRecord(item["inputSchema"]) ? item["inputSchema"] : undefined,
          annotations: isRecord(item["annotations"]) ? item["annotations"] : undefined,
        });
      }
    }
    return tools;
  }

  async listPrompts(): Promise<McpPromptDefinition[]> {
    const items = await this.paginate("prompts/list", "prompts");
    const prompts: McpPromptDefinition[] = [];
    for (const item of items) {
      if (isRecord(item) && typeof item["name"] === "string") {
        const args: { name: string; description?: string; required?: boolean }[] = [];
        if (Array.isArray(item["arguments"])) {
          for (const a of item["arguments"]) {
            if (isRecord(a) && typeof a["name"] === "string") {
              args.push({
                name: a["name"],
                description: typeof a["description"] === "string" ? a["description"] : undefined,
                required: typeof a["required"] === "boolean" ? a["required"] : undefined,
              });
            }
          }
        }
        prompts.push({
          name: item["name"],
          description: typeof item["description"] === "string" ? item["description"] : undefined,
          arguments: args,
        });
      }
    }
    return prompts;
  }

  async listResources(): Promise<McpResourceDefinition[]> {
    const items = await this.paginate("resources/list", "resources");
    const resources: McpResourceDefinition[] = [];
    for (const item of items) {
      if (isRecord(item) && typeof item["uri"] === "string") {
        resources.push({
          uri: item["uri"],
          name: typeof item["name"] === "string" ? item["name"] : undefined,
          description: typeof item["description"] === "string" ? item["description"] : undefined,
          mimeType: typeof item["mimeType"] === "string" ? item["mimeType"] : undefined,
        });
      }
    }
    return resources;
  }

  async callTool(name: string, args: unknown, timeoutMs?: number): Promise<RpcOutcome> {
    return this.request("tools/call", { name, arguments: args }, timeoutMs ?? this.defaultTimeoutMs);
  }

  async readResource(uri: string, timeoutMs?: number): Promise<RpcOutcome> {
    return this.request("resources/read", { uri }, timeoutMs ?? this.defaultTimeoutMs);
  }

  async request(method: string, params: unknown, timeoutMs: number): Promise<RpcOutcome> {
    const id = this.nextId++;
    const frame: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
    return this.dispatch(String(id), method, JSON.stringify(frame), timeoutMs);
  }

  /**
   * Sends a raw (possibly malformed) frame and waits for whatever the server
   * responds with. If `expectId` is given, the response with that id resolves
   * the outcome; otherwise any frame (or silence until timeout) resolves it.
   */
  async sendRaw(raw: string, timeoutMs: number, expectId?: JsonRpcId): Promise<RpcOutcome> {
    const key = expectId === undefined || expectId === null ? `raw:${this.nextId++}` : String(expectId);
    if (expectId === undefined || expectId === null) {
      this.rawWaiters.push(key);
    }
    return this.dispatch(key, "raw", raw, timeoutMs);
  }

  private readonly rawWaiters: string[] = [];

  async notify(method: string, params: unknown): Promise<void> {
    const frame = JSON.stringify({ jsonrpc: "2.0", method, params });
    try {
      await this.transport.send(frame);
    } catch (err) {
      this.log.warn("notification send failed", { method, error: errorMessage(err) });
    }
  }

  private dispatch(key: string, method: string, frame: string, timeoutMs: number): Promise<RpcOutcome> {
    return new Promise<RpcOutcome>((resolve) => {
      const startedAt = Date.now();
      const timer = setTimeout(() => {
        this.pending.delete(key);
        const idx = this.rawWaiters.indexOf(key);
        if (idx >= 0) {
          this.rawWaiters.splice(idx, 1);
        }
        const latencyMs = Date.now() - startedAt;
        // For raw/malformed frames silence is an acceptable answer, not a hang.
        const isRaw = key.startsWith("raw:");
        resolve({ ok: false, hang: !isRaw, crashed: false, latencyMs, transportError: isRaw ? "no response" : "timeout" });
      }, timeoutMs);
      this.pending.set(key, { resolve, timer, startedAt, method });
      this.transport.send(frame).catch((err: unknown) => {
        const entry = this.pending.get(key);
        if (!entry) {
          return;
        }
        clearTimeout(entry.timer);
        this.pending.delete(key);
        const crashed = err instanceof TargetCrashError;
        if (crashed) {
          this.crashEvents += 1;
        }
        resolve({
          ok: false,
          hang: false,
          crashed,
          latencyMs: Date.now() - startedAt,
          transportError: errorMessage(err),
        });
      });
    });
  }

  private async paginate(method: string, field: string): Promise<unknown[]> {
    const items: unknown[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 50; page++) {
      const params = cursor ? { cursor } : {};
      const outcome = await this.request(method, params, this.defaultTimeoutMs);
      if (outcome.crashed) {
        throw new TargetCrashError(outcome.transportError ?? `target crashed during ${method}`);
      }
      if (!outcome.ok) {
        if (outcome.error && (outcome.error.code === -32601 || /not (supported|found)/i.test(outcome.error.message))) {
          return items;
        }
        if (outcome.hang) {
          this.log.warn("list request hung", { method });
          return items;
        }
        this.log.warn("list request failed", { method, error: outcome.error ?? outcome.transportError });
        return items;
      }
      if (!isRecord(outcome.result)) {
        return items;
      }
      const list = outcome.result[field];
      if (Array.isArray(list)) {
        items.push(...list);
      }
      const next = outcome.result["nextCursor"];
      if (typeof next === "string" && next.length > 0 && next !== cursor) {
        cursor = next;
      } else {
        break;
      }
    }
    return items;
  }

  private handleFrame(frame: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(frame);
    } catch (err) {
      this.recordMalformed(frame, `invalid JSON: ${errorMessage(err)}`);
      this.resolveRawWaiter(frame);
      return;
    }
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        this.handleMessage(item, frame);
      }
      return;
    }
    this.handleMessage(parsed, frame);
  }

  private handleMessage(message: unknown, raw: string): void {
    if (!isRecord(message)) {
      this.recordMalformed(raw, "frame is not a JSON object");
      this.resolveRawWaiter(raw);
      return;
    }
    if (message["jsonrpc"] !== "2.0") {
      this.recordMalformed(raw, "missing or invalid jsonrpc version field");
      this.resolveRawWaiter(raw);
      return;
    }
    const hasId = "id" in message && message["id"] !== undefined;
    const hasMethod = typeof message["method"] === "string";
    if (hasMethod && hasId) {
      // Server -> client request (sampling, roots, elicitation, ...)
      const method = message["method"] as string;
      this.unsolicited.set(method, (this.unsolicited.get(method) ?? 0) + 1);
      this.log.warn("unsolicited server request", { method });
      const reply = JSON.stringify({
        jsonrpc: "2.0",
        id: message["id"] as JsonRpcId,
        error: { code: -32601, message: "Method not supported by evaluator" },
      });
      this.transport.send(reply).catch(() => undefined);
      return;
    }
    if (hasMethod) {
      this.notificationsCount += 1;
      return;
    }
    if (!hasId) {
      this.recordMalformed(raw, "response without id");
      this.resolveRawWaiter(raw);
      return;
    }
    const idValue = message["id"];
    const key = idValue === null ? "null" : String(idValue as string | number);
    const pending = this.pending.get(key);
    if (!pending) {
      if (!this.resolveRawWaiter(raw)) {
        this.log.debug("response for unknown request id", { id: key });
      }
      return;
    }
    clearTimeout(pending.timer);
    this.pending.delete(key);
    const latencyMs = Date.now() - pending.startedAt;
    this.latency.record(latencyMs);
    const hasResult = "result" in message;
    const errorField = message["error"];
    if (isRecord(errorField) && typeof errorField["code"] === "number" && typeof errorField["message"] === "string") {
      const rpcError: JsonRpcError = {
        code: errorField["code"],
        message: errorField["message"],
        data: errorField["data"],
      };
      pending.resolve({ ok: false, error: rpcError, hang: false, crashed: false, latencyMs });
      return;
    }
    if (!hasResult) {
      this.recordMalformed(raw, "response has neither result nor error");
      pending.resolve({ ok: false, hang: false, crashed: false, latencyMs, transportError: "malformed response" });
      return;
    }
    pending.resolve({ ok: true, result: message["result"], hang: false, crashed: false, latencyMs });
  }

  private resolveRawWaiter(raw: string): boolean {
    const key = this.rawWaiters.shift();
    if (!key) {
      return false;
    }
    const pending = this.pending.get(key);
    if (!pending) {
      return false;
    }
    clearTimeout(pending.timer);
    this.pending.delete(key);
    const latencyMs = Date.now() - pending.startedAt;
    this.latency.record(latencyMs);
    let parsed: unknown = undefined;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = raw;
    }
    if (isRecord(parsed) && isRecord(parsed["error"]) && typeof parsed["error"]["code"] === "number") {
      const e = parsed["error"];
      pending.resolve({
        ok: false,
        error: { code: e["code"] as number, message: String(e["message"] ?? ""), data: e["data"] },
        hang: false,
        crashed: false,
        latencyMs,
      });
    } else {
      pending.resolve({ ok: true, result: parsed, hang: false, crashed: false, latencyMs });
    }
    return true;
  }

  private recordMalformed(raw: string, detail: string): void {
    this.malformedCount += 1;
    const err = new MalformedFrameError(raw.slice(0, 512), detail);
    this.lastMalformed = err;
    this.log.warn("malformed frame from target", { detail, excerpt: raw.slice(0, 200) });
  }

  get lastMalformedFrame(): MalformedFrameError | null {
    return this.lastMalformed;
  }

  private handleClose(reason: string): void {
    this.crashEvents += 1;
    for (const [key, req] of this.pending.entries()) {
      clearTimeout(req.timer);
      this.pending.delete(key);
      req.resolve({
        ok: false,
        hang: false,
        crashed: true,
        latencyMs: Date.now() - req.startedAt,
        transportError: `target connection lost: ${reason}`,
      });
    }
    this.rawWaiters.length = 0;
  }

  /** Reconnects the transport and re-runs the initialize handshake. */
  async recover(maxWaitMs: number): Promise<boolean> {
    try {
      await this.transport.reconnect();
    } catch (err) {
      this.log.warn("reconnect failed", { error: errorMessage(err) });
      return false;
    }
    try {
      await this.initializeWithRetry(maxWaitMs);
      return true;
    } catch (err) {
      this.log.warn("re-initialize failed", { error: errorMessage(err) });
      return false;
    }
  }
}

export function extractText(result: unknown): string {
  if (!isRecord(result)) {
    return typeof result === "string" ? result : JSON.stringify(result ?? null);
  }
  const parts: string[] = [];
  const content = result["content"];
  if (Array.isArray(content)) {
    for (const block of content) {
      if (isRecord(block)) {
        if (typeof block["text"] === "string") {
          parts.push(block["text"]);
        } else if (typeof block["data"] === "string") {
          parts.push(`[${String(block["mimeType"] ?? "binary")} ${block["data"].length} bytes base64]`);
        } else {
          parts.push(JSON.stringify(block));
        }
      }
    }
  }
  if (result["structuredContent"] !== undefined) {
    parts.push(JSON.stringify(result["structuredContent"]));
  }
  if (parts.length === 0) {
    return JSON.stringify(result);
  }
  return parts.join("\n");
}

export function isToolError(result: unknown): boolean {
  return isRecord(result) && result["isError"] === true;
}

export function asToolCallResult(result: unknown): McpToolCallResult | null {
  return isRecord(result) ? (result as McpToolCallResult) : null;
}
