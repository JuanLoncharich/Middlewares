import type { MCPEvaluationRun, MCPEvaluationRunStatus, MCPServer, OpenCodeAgent } from "../model/crd.ts";
import type { Redaction, TripExtras } from "../model/flow.ts";
import type { LogLine } from "../model/logs.ts";
import type { EvaluationReport } from "../model/report.ts";

export type Mode = "demo" | "live";

export interface Connection {
  state: "connecting" | "open" | "error";
  message?: string;
}

/** Everything the views read. Demo and live fill the same shape. */
export interface Snapshot {
  servers: Record<string, MCPServer>;
  runs: Record<string, MCPEvaluationRun>;
  agents: Record<string, OpenCodeAgent>;
  /** runName → report from the `<run>-report` ConfigMap. */
  reports: Record<string, EvaluationReport>;
  /** runName → evaluator log lines (only for runs someone followed). */
  logs: Record<string, LogLine[]>;
  /** runName → agent → per-call detail. Demo only. */
  extras: Record<string, Record<string, TripExtras>>;
  /** Gateway-wide Occludra redaction counts (live, when PROM_URL is set). */
  gateway: { redactions: Redaction[]; window: string } | null;
  connection: Connection;
}

export interface ReplayState {
  scenario: string;
  playing: boolean;
  speed: number;
  elapsedMs: number;
  durationMs: number;
}

export interface DataSource {
  readonly mode: Mode;
  getSnapshot(): Snapshot;
  subscribe(listener: () => void): () => void;
  start(): void;
  stop(): void;
  /** Ask for the evaluator log of a run (live streams it; demo already has it). */
  follow(run: string | null): void;
}

export function emptySnapshot(connection: Connection = { state: "open" }): Snapshot {
  return { servers: {}, runs: {}, agents: {}, reports: {}, logs: {}, extras: {}, gateway: null, connection };
}

/**
 * Applies a status patch the way the runner sends it (JSON merge patch on the
 * status subresource): agentResults merges key by key, everything else replaces.
 */
export function mergeRunStatus(prev: MCPEvaluationRunStatus | undefined, patch: Partial<MCPEvaluationRunStatus>): MCPEvaluationRunStatus {
  const next: MCPEvaluationRunStatus = { ...prev, ...patch };
  if (patch.agentResults) next.agentResults = { ...prev?.agentResults, ...patch.agentResults };
  return next;
}

/** Runs of a server, newest first. */
export function runsOf(snapshot: Snapshot, server: string): MCPEvaluationRun[] {
  return Object.values(snapshot.runs)
    .filter((r) => r.spec.serverRef === server)
    .sort((a, b) => (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""));
}
