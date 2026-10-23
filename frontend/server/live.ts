// Live backend for the UI: watches the CRs with read-only credentials and
// pushes them over one WebSocket (/api/stream). It never writes to the
// cluster, never execs into a pod and only reads the `evaluator` container's
// log: the target's output is untrusted and stays out of the UI.
//
// Env: KUBECONFIG (or in-cluster), NAMESPACE (mcp-evals), PORT (8787),
// HOST (127.0.0.1), PROM_URL (optional, for Occludra redaction counts),
// NODE_ENV=production to also serve the built UI from dist/, and the chat's
// CHAT_URL / CHAT_MODEL / OCCLUDRA_INSPECT_URL (see chat.ts). The chat is the
// one route that sends something: a question to the tool-less OpenCode
// server. Nothing here writes to the cluster.
import * as k8s from "@kubernetes/client-node";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { WebSocket, WebSocketServer } from "ws";
import type { ClientMessage, ServerMessage } from "../src/data/live.ts";
import { API_VERSION, LABEL_RUN, type MCPEvaluationRun, isTerminal } from "../src/model/crd.ts";
import { type LogLine, parseLogLine } from "../src/model/logs.ts";
import type { EvaluationReport } from "../src/model/report.ts";
import { chatEnabled, handleChat } from "./chat.ts";
import { isSameOrigin } from "./origin.ts";

const NAMESPACE = process.env["NAMESPACE"] ?? "mcp-evals";
const PORT = Number(process.env["PORT"] ?? 8787);
const HOST = process.env["HOST"] ?? "127.0.0.1";
const PROM_URL = process.env["PROM_URL"] ?? "";
const PRODUCTION = process.env["NODE_ENV"] === "production";
const DIST = resolve(fileURLToPath(new URL("../dist", import.meta.url)));

const GROUP = "security.eval.io";
const VERSION = API_VERSION.split("/")[1]!;
const RESOURCES = [
  { resource: "servers", plural: "mcpservers" },
  { resource: "runs", plural: "mcpevaluationruns" },
  { resource: "agents", plural: "opencodeagents" },
] as const;
type Resource = (typeof RESOURCES)[number]["resource"];

const LOG_BATCH_MS = 200;
const RETRY_MS = 3000;
const PROM_EVERY_MS = 30_000;

function log(msg: string, fields: Record<string, unknown> = {}): void {
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), component: "mcp-eval-ui", msg, ...fields }) + "\n");
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const kc = new k8s.KubeConfig();
kc.loadFromDefault();
const custom = kc.makeApiClient(k8s.CustomObjectsApi);
const core = kc.makeApiClient(k8s.CoreV1Api);
const logApi = new k8s.Log(kc);

// --- state -------------------------------------------------------------------

type Obj = k8s.KubernetesObject & { metadata: k8s.V1ObjectMeta };
const store: Record<Resource, Map<string, Obj>> = { servers: new Map(), runs: new Map(), agents: new Map() };
const reports = new Map<string, EvaluationReport>();
const clients = new Set<Client>();
let lastError: string | null = null;

function slim<T extends Obj>(o: T): T {
  // managedFields is large and useless to the UI.
  const { managedFields: _drop, ...metadata } = o.metadata;
  void _drop;
  return { ...o, metadata } as T;
}

function broadcast(msg: ServerMessage): void {
  const data = JSON.stringify(msg);
  for (const c of clients) if (c.ws.readyState === WebSocket.OPEN) c.ws.send(data);
}

function snapshotMessage(): ServerMessage {
  return {
    type: "snapshot",
    namespace: NAMESPACE,
    servers: [...store.servers.values()] as never,
    runs: [...store.runs.values()] as never,
    agents: [...store.agents.values()] as never,
  };
}

// --- informers -----------------------------------------------------------------

function watch(resource: Resource, plural: string): void {
  const path = `/apis/${GROUP}/${VERSION}/namespaces/${NAMESPACE}/${plural}`;
  const list = () =>
    custom.listNamespacedCustomObject({ group: GROUP, version: VERSION, namespace: NAMESPACE, plural }) as Promise<
      k8s.KubernetesListObject<Obj>
    >;
  const informer = k8s.makeInformer<Obj>(kc, path, list);
  const upsert = (o: Obj) => {
    const obj = slim(o);
    store[resource].set(obj.metadata.name!, obj);
    broadcast({ type: "upsert", resource, object: obj as never });
    if (resource === "runs") void maybeFetchReport(obj as unknown as MCPEvaluationRun);
  };
  informer.on(k8s.ADD, upsert);
  informer.on(k8s.UPDATE, upsert);
  informer.on(k8s.DELETE, (o: Obj) => {
    store[resource].delete(o.metadata.name!);
    broadcast({ type: "delete", resource, name: o.metadata.name! });
  });
  informer.on(k8s.ERROR, (err: unknown) => {
    lastError = `No se pudo leer ${plural} en ${NAMESPACE}: ${errorMessage(err)}`;
    log("watch failed; restarting", { plural, error: errorMessage(err) });
    broadcast({ type: "error", message: lastError });
    setTimeout(() => void informer.start().catch(() => {}), RETRY_MS);
  });
  informer.on(k8s.CONNECT, () => {
    if (lastError) {
      lastError = null;
      broadcast(snapshotMessage());
    }
  });
  informer.start().catch((err: unknown) => {
    lastError = `No se pudo leer ${plural} en ${NAMESPACE}: ${errorMessage(err)}`;
    log("watch start failed", { plural, error: errorMessage(err) });
  });
}

// --- reports -------------------------------------------------------------------

const REPORT_ATTEMPTS = 6;
const reportPending = new Set<string>();

/**
 * The evaluator patches the terminal phase before it writes the ConfigMap
 * (a Vigil abort patches Failed first), so a 404 right after is retried.
 */
async function maybeFetchReport(run: MCPEvaluationRun, attempt = 1): Promise<void> {
  const name = run.metadata.name;
  if (!isTerminal(run.status?.phase) || reports.has(name)) return;
  if (attempt === 1) {
    if (reportPending.has(name)) return;
    reportPending.add(name);
  }
  try {
    const cm = await core.readNamespacedConfigMap({ name: `${name}-report`, namespace: NAMESPACE });
    // Oversized reports keep a summary plus a truncated copy (runner/src/k8s.ts).
    const raw = cm.data?.["report.json"] ?? cm.data?.["report.truncated.json"];
    if (!raw) return;
    const report = JSON.parse(raw) as EvaluationReport;
    reports.set(name, report);
    reportPending.delete(name);
    broadcast({ type: "report", run: name, report });
  } catch (err) {
    if (attempt < REPORT_ATTEMPTS) {
      setTimeout(() => void maybeFetchReport(run, attempt + 1), RETRY_MS);
      return;
    }
    reportPending.delete(name);
    log("report not available", { run: name, error: errorMessage(err) });
  }
}

// --- evaluator logs ------------------------------------------------------------

class LogFollower {
  private abort: AbortController | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private pending: LogLine[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private first = true;

  constructor(
    private readonly run: string,
    private readonly send: (msg: ServerMessage) => void,
  ) {
    void this.attach();
  }

  stop(): void {
    this.stopped = true;
    this.abort?.abort();
    if (this.timer) clearTimeout(this.timer);
    if (this.flushTimer) clearTimeout(this.flushTimer);
  }

  private retry(): void {
    if (this.stopped) return;
    const run = store.runs.get(this.run) as MCPEvaluationRun | undefined;
    if (run && isTerminal(run.status?.phase) && !this.first) return;
    this.timer = setTimeout(() => void this.attach(), RETRY_MS);
  }

  private async attach(): Promise<void> {
    if (this.stopped) return;
    let pod: k8s.V1Pod | undefined;
    try {
      const pods = await core.listNamespacedPod({ namespace: NAMESPACE, labelSelector: `${LABEL_RUN}=${this.run}` });
      pod = pods.items.sort((a, b) =>
        String(b.metadata?.creationTimestamp ?? "").localeCompare(String(a.metadata?.creationTimestamp ?? "")),
      )[0];
    } catch (err) {
      log("pod lookup failed", { run: this.run, error: errorMessage(err) });
    }
    const started = pod?.status?.containerStatuses?.find((c) => c.name === "evaluator")?.state;
    if (!pod?.metadata?.name || !started || started.waiting) {
      this.retry();
      return;
    }
    const stream = new PassThrough();
    let buffer = "";
    stream.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      const parts = buffer.split("\n");
      buffer = parts.pop() ?? "";
      for (const p of parts) {
        const line = parseLogLine(p);
        if (line) this.push(line);
      }
    });
    stream.on("end", () => {
      this.flush();
      this.retry();
    });
    try {
      // Re-attaching replays the whole log, so the client resets its copy.
      this.reset = true;
      this.abort = await logApi.log(NAMESPACE, pod.metadata.name, "evaluator", stream, { follow: true, pretty: false, timestamps: false });
      this.first = false;
    } catch (err) {
      log("log stream failed", { run: this.run, error: errorMessage(err) });
      this.retry();
    }
  }

  private reset = false;

  private push(line: LogLine): void {
    this.pending.push(line);
    this.flushTimer ??= setTimeout(() => this.flush(), LOG_BATCH_MS);
  }

  private flush(): void {
    this.flushTimer = null;
    if (this.pending.length === 0) return;
    this.send({ type: "log", run: this.run, lines: this.pending, reset: this.reset });
    this.reset = false;
    this.pending = [];
  }
}

// --- clients -------------------------------------------------------------------

class Client {
  private follower: LogFollower | null = null;

  constructor(readonly ws: WebSocket) {
    this.send(snapshotMessage());
    for (const [run, report] of reports) this.send({ type: "report", run, report });
    if (lastError) this.send({ type: "error", message: lastError });
    ws.on("message", (data) => {
      let msg: ClientMessage;
      try {
        msg = JSON.parse(String(data)) as ClientMessage;
      } catch {
        return;
      }
      if (msg.type === "follow") this.follow(typeof msg.run === "string" ? msg.run : null);
    });
    ws.on("close", () => {
      this.follower?.stop();
      clients.delete(this);
    });
  }

  send(msg: ServerMessage): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  private follow(run: string | null): void {
    this.follower?.stop();
    this.follower = null;
    if (!run || !/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(run)) return;
    const known = store.runs.get(run) as MCPEvaluationRun | undefined;
    if (known) void maybeFetchReport(known);
    this.follower = new LogFollower(run, (m) => this.send(m));
  }
}

// --- Occludra counters ---------------------------------------------------------

async function pollPrometheus(): Promise<void> {
  const query = "sum by (detector) (increase(occludra_redactions_total[15m]))";
  try {
    const res = await fetch(`${PROM_URL.replace(/\/$/, "")}/api/v1/query?query=${encodeURIComponent(query)}`);
    const body = (await res.json()) as { data?: { result?: { metric: { detector?: string }; value: [number, string] }[] } };
    const redactions = (body.data?.result ?? [])
      .map((r) => ({ detector: r.metric.detector ?? "?", count: Math.round(Number(r.value[1])) }))
      .filter((r) => r.count > 0)
      .sort((a, b) => b.count - a.count);
    broadcast({ type: "gateway", redactions, window: "los últimos 15 minutos" });
  } catch (err) {
    log("prometheus query failed", { error: errorMessage(err) });
  }
}

// --- http ----------------------------------------------------------------------

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};

/** Hashes of index.html's inline scripts (the pre-paint theme switch), for the CSP. */
function inlineScriptHashes(): string {
  const index = join(DIST, "index.html");
  if (!existsSync(index)) return "";
  const html = readFileSync(index, "utf8");
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map((m) => ` 'sha256-${createHash("sha256").update(m[1]!).digest("base64")}'`)
    .join("");
}

const CSP = PRODUCTION
  ? `default-src 'self'; script-src 'self'${inlineScriptHashes()}; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data:`
  : "";

function serveStatic(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? "/", "http://x");
  const rel = normalize(decodeURIComponent(url.pathname)).replace(/^([/\\])+/, "");
  let file = resolve(join(DIST, rel));
  // DIST + sep: a bare prefix check would also accept a sibling like dist-old/.
  if (file !== DIST && !file.startsWith(DIST + sep)) {
    res.writeHead(403).end();
    return;
  }
  if (!existsSync(file) || statSync(file).isDirectory()) file = join(DIST, "index.html");
  res.writeHead(200, {
    "content-type": TYPES[extname(file)] ?? "application/octet-stream",
    "x-content-type-options": "nosniff",
    "content-security-policy": CSP,
  });
  createReadStream(file).pipe(res);
}

const server = createServer((req, res) => {
  if (req.url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" }).end("ok");
    return;
  }
  if (req.url === "/api/chat") {
    void handleChat(req, res);
    return;
  }
  if (PRODUCTION) {
    serveStatic(req, res);
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" }).end("UI served by vite in development (npm run live)");
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 4096 });
server.on("upgrade", (req, socket, head) => {
  if (!req.url?.startsWith("/api/stream")) {
    socket.destroy();
    return;
  }
  if (!isSameOrigin(req.headers.origin, req.headers.host)) {
    log("websocket from another origin refused", { origin: req.headers.origin });
    socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => clients.add(new Client(ws)));
});

for (const { resource, plural } of RESOURCES) watch(resource, plural);
if (PROM_URL) {
  void pollPrometheus();
  setInterval(() => void pollPrometheus(), PROM_EVERY_MS);
}

server.listen(PORT, HOST, () => {
  log("listening", { url: `http://${HOST}:${PORT}`, namespace: NAMESPACE, context: kc.getCurrentContext(), prometheus: PROM_URL || "off", chat: chatEnabled ? "on" : "off" });
});
