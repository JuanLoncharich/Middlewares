import { useEffect, useMemo, useRef, useState } from "react";
import type { MCPEvaluationRun, MCPServer, RunPhase } from "../model/crd.ts";
import { type Trip, deriveTrips } from "../model/flow.ts";
import type { LogLine } from "../model/logs.ts";
import type { EvaluationReport } from "../model/report.ts";
import type { Snapshot } from "./source.ts";

export interface RunData {
  run: MCPEvaluationRun | undefined;
  server: MCPServer | undefined;
  report: EvaluationReport | undefined;
  logs: LogLine[];
  trips: Trip[];
}

const NO_LOGS: LogLine[] = [];

export function useRun(snap: Snapshot, runName: string | null): RunData {
  const run = runName ? snap.runs[runName] : undefined;
  const report = runName ? snap.reports[runName] : undefined;
  const logs = (runName && snap.logs[runName]) || NO_LOGS;
  const extras = runName ? snap.extras[runName] : undefined;
  const trips = useMemo(() => deriveTrips(logs, report, extras), [logs, report, extras]);
  return { run, server: run ? snap.servers[run.spec.serverRef] : undefined, report, logs, trips };
}

/**
 * The CR keeps no per-phase timestamps, so the UI remembers when it saw each
 * phase. Runs that were already past a phase when we connected show no time.
 */
export function usePhaseTimes(run: MCPEvaluationRun | undefined, now: number): Partial<Record<RunPhase, string>> {
  const seen = useRef<Record<string, Partial<Record<RunPhase, string>>>>({});
  const name = run?.metadata.name;
  const phase = run?.status?.phase;
  if (name && phase) {
    const times = (seen.current[name] ??= {});
    if (run.status?.startTime) times.Pending ??= run.status.startTime;
    if (phase === "Completed" || phase === "Failed") times[phase] ??= run.status?.completionTime ?? new Date(now).toISOString();
    else times[phase] ??= new Date(now).toISOString();
  }
  return (name && seen.current[name]) || {};
}

/**
 * The time views should draw against: the replay's virtual clock in demo,
 * the wall clock (refreshed every `ms` while `active`) in live.
 */
export function useNow(snapNow: number | null, active: boolean, ms = 1000): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (!active || snapNow !== null) return;
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [active, ms, snapNow]);
  return snapNow ?? now;
}
