// One server's state as the list and the server page show it.
import { type MCPEvaluationRun, type MCPServer, type RiskCategory, isTerminal } from "./crd.ts";
import { type Snapshot, runsOf } from "../data/source.ts";

export type VerdictKind = "safe" | "caution" | "untrusted" | "malicious" | "running" | "paused" | "error" | "none";

export interface ServerState {
  kind: VerdictKind;
  label: string;
  score?: number;
  latest?: MCPEvaluationRun;
  /** The newest run that ended with a verdict. */
  judged?: MCPEvaluationRun;
  running?: MCPEvaluationRun;
  runs: MCPEvaluationRun[];
}

export const RISK_KIND: Record<Exclude<RiskCategory, "Unknown">, { kind: VerdictKind; label: string }> = {
  Safe: { kind: "safe", label: "Seguro" },
  Caution: { kind: "caution", label: "Con cuidado" },
  Untrusted: { kind: "untrusted", label: "No confiable" },
  Malicious: { kind: "malicious", label: "Malicioso" },
};

export function serverState(snap: Snapshot, server: MCPServer): ServerState {
  const runs = runsOf(snap, server.metadata.name);
  const latest = runs[0];
  const running = runs.find((r) => !isTerminal(r.status?.phase));
  const judged = runs.find((r) => {
    const risk = r.status?.scoring?.riskCategory;
    return isTerminal(r.status?.phase) && risk && risk !== "Unknown";
  });
  const risk = (judged?.status?.scoring?.riskCategory ?? server.status?.overallRiskStatus) as RiskCategory | undefined;
  const base = { latest, judged, running, runs };
  if (running) return { ...base, kind: "running", label: "Evaluando" };
  if (server.spec.active === false) return { ...base, kind: "paused", label: "Pausado", score: judged?.status?.scoring?.safetyScore };
  if (risk && risk !== "Unknown") {
    return { ...base, ...RISK_KIND[risk], score: judged?.status?.scoring?.safetyScore ?? server.status?.lastFinalScore };
  }
  if (latest?.status?.phase === "Failed") return { ...base, kind: "error", label: "Falló la evaluación" };
  return { ...base, kind: "none", label: "Sin evaluar" };
}
