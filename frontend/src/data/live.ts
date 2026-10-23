// Live data source: a WebSocket to server/live.ts, which watches the CRs with
// read-only credentials. Messages carry whole objects, so the views get the
// same shapes as in demo mode.
import type { MCPEvaluationRun, MCPServer, OpenCodeAgent } from "../model/crd.ts";
import type { Redaction } from "../model/flow.ts";
import type { LogLine } from "../model/logs.ts";
import type { EvaluationReport } from "../model/report.ts";
import { type DataSource, type Snapshot, emptySnapshot } from "./source.ts";

type Resource = "servers" | "runs" | "agents";
type Obj = MCPServer | MCPEvaluationRun | OpenCodeAgent;

export type ServerMessage =
  | { type: "snapshot"; servers: MCPServer[]; runs: MCPEvaluationRun[]; agents: OpenCodeAgent[]; namespace: string }
  | { type: "upsert"; resource: Resource; object: Obj }
  | { type: "delete"; resource: Resource; name: string }
  | { type: "report"; run: string; report: EvaluationReport }
  | { type: "log"; run: string; lines: LogLine[]; reset?: boolean }
  | { type: "gateway"; redactions: Redaction[]; window: string }
  | { type: "error"; message: string };

export type ClientMessage = { type: "follow"; run: string | null };

const RETRY_MS = 3000;

function byName<T extends Obj>(items: T[]): Record<string, T> {
  return Object.fromEntries(items.map((o) => [o.metadata.name, o]));
}

export class LiveSource implements DataSource {
  readonly mode = "live" as const;
  private snap: Snapshot = emptySnapshot({ state: "connecting" });
  private readonly listeners = new Set<() => void>();
  private ws: WebSocket | null = null;
  private retry: ReturnType<typeof setTimeout> | null = null;
  private following: string | null = null;
  private stopped = true;

  constructor(private readonly url = LiveSource.defaultUrl()) {}

  static defaultUrl(): string {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${location.host}/api/stream`;
  }

  getSnapshot = (): Snapshot => this.snap;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.retry) clearTimeout(this.retry);
    this.ws?.close();
    this.ws = null;
  }

  follow(run: string | null): void {
    this.following = run;
    this.send({ type: "follow", run });
  }

  private send(msg: ClientMessage): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  private connect(): void {
    if (this.stopped) return;
    this.set({ connection: { state: "connecting" } });
    const ws = new WebSocket(this.url);
    this.ws = ws;
    ws.onopen = () => {
      this.set({ connection: { state: "open" } });
      if (this.following) this.send({ type: "follow", run: this.following });
    };
    ws.onmessage = (ev) => {
      try {
        this.handle(JSON.parse(String(ev.data)) as ServerMessage);
      } catch {
        // A malformed frame is dropped; the next snapshot repairs state.
      }
    };
    ws.onclose = () => {
      if (this.stopped) return;
      this.set({
        connection: {
          state: "error",
          message: "No hay conexión con el backend live. Levantalo con npm run live y revisá que KUBECONFIG apunte al cluster.",
        },
      });
      this.retry = setTimeout(() => this.connect(), RETRY_MS);
    };
  }

  private handle(msg: ServerMessage): void {
    const s = this.snap;
    switch (msg.type) {
      case "snapshot":
        this.set({ servers: byName(msg.servers), runs: byName(msg.runs), agents: byName(msg.agents), connection: { state: "open" } });
        break;
      case "upsert":
        this.set({ [msg.resource]: { ...s[msg.resource], [msg.object.metadata.name]: msg.object } });
        break;
      case "delete": {
        const next = { ...s[msg.resource] };
        delete next[msg.name];
        this.set({ [msg.resource]: next });
        break;
      }
      case "report":
        this.set({ reports: { ...s.reports, [msg.run]: msg.report } });
        break;
      case "log": {
        const prev = msg.reset ? [] : (s.logs[msg.run] ?? []);
        this.set({ logs: { ...s.logs, [msg.run]: [...prev, ...msg.lines] } });
        break;
      }
      case "gateway":
        this.set({ gateway: { redactions: msg.redactions, window: msg.window } });
        break;
      case "error":
        this.set({ connection: { state: "error", message: msg.message } });
        break;
    }
  }

  private set(patch: Partial<Snapshot>): void {
    this.snap = { ...this.snap, ...patch };
    for (const l of this.listeners) l();
  }
}
