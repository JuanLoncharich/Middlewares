// Reconstructs the path of each LLM call ("trip") from what the evaluator
// actually emits: its log lines while the run is in flight, enriched with the
// report once the run ends. Demo and live go through the same function.
import type { MCPEvaluationRun } from "./crd.ts";
import { isTerminal, verdictOf } from "./crd.ts";
import type { LogLine } from "./logs.ts";
import type { AgentKind, EvaluationReport, VigilDetectionRecord, VigilWarningRecord } from "./report.ts";

export type StationId = "source" | "vigil" | "prompt" | "occludra" | "netbird" | "llm" | "agent" | "synthesis" | "verdict";

export interface StationInfo {
  id: StationId;
  name: string;
  role: string;
}

export const STATIONS: StationInfo[] = [
  { id: "source", name: "Servidor MCP", role: "Texto no confiable: tools, prompts, respuestas" },
  { id: "vigil", name: "Vigil", role: "Detecta prompt injection con tres escáneres" },
  { id: "prompt", name: "Prompt", role: "La evidencia se arma como mensaje para el agente" },
  { id: "occludra", name: "Occludra", role: "Enmascara datos personales y credenciales" },
  { id: "netbird", name: "NetBird", role: "Túnel WireGuard; única salida del sandbox" },
  { id: "llm", name: "Modelo", role: "Proveedor LLM vía OpenCode Zen" },
  { id: "agent", name: "Agente", role: "Respuesta estructurada en JSON" },
  { id: "synthesis", name: "Síntesis", role: "SynthesisScorer combina los cuatro informes" },
  { id: "verdict", name: "Veredicto", role: "Puntaje y riesgo escritos en el CR" },
];

export type ScanStatus = "pass" | "warn" | "block" | "unavailable";

export interface VigilScan {
  source: string;
  at: string;
  status: ScanStatus;
  units?: number;
  warnings: number;
  confidence?: number;
  scanners: string[];
  /** Per-scanner detail, only once the report exists. */
  warningRecords?: VigilWarningRecord[];
  detection?: VigilDetectionRecord;
}

export interface Redaction {
  detector: string;
  count: number;
  /** Already-masked samples; only the demo has them (Occludra never logs content). */
  examples?: string[];
}

/** Detail the live system does not expose per call; the demo fills it in. */
export interface TripExtras {
  redactions?: Redaction[];
  latencyMs?: Partial<Record<StationId, number>>;
  promptBytes?: number;
}

export type TripStatus = "running" | "ok" | "failed" | "blocked";

export interface Trip {
  id: string;
  agent: string;
  kind?: AgentKind;
  model?: string;
  startedAt: string;
  endedAt?: string;
  durationMs?: number;
  status: TripStatus;
  error?: string;
  scans: VigilScan[];
  extras?: TripExtras;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function num(v: unknown): number | undefined {
  return typeof v === "number" ? v : undefined;
}
function strs(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [];
}

export function deriveTrips(
  logs: LogLine[],
  report?: EvaluationReport | null,
  extras?: Record<string, TripExtras>,
): Trip[] {
  const trips: Trip[] = [];
  const current = (): Trip | undefined => {
    const last = trips[trips.length - 1];
    return last && last.status === "running" ? last : undefined;
  };
  // A Vigil abort can happen with no agent around it in a custom suite; give it a trip.
  const holder = (at: string): Trip => {
    const t = current();
    if (t) return t;
    const orphan: Trip = { id: `scan-${trips.length}`, agent: "evaluator", startedAt: at, status: "running", scans: [] };
    trips.push(orphan);
    return orphan;
  };

  for (const line of logs) {
    switch (line.msg) {
      case "agent start": {
        const agent = str(line["agent"]) ?? "agent";
        trips.push({
          id: `${agent}-${trips.length}`,
          agent,
          kind: str(line["kind"]) as AgentKind | undefined,
          model: str(line["model"]),
          startedAt: line.ts,
          status: "running",
          scans: [],
          extras: extras?.[agent],
        });
        break;
      }
      case "agent done": {
        const t = current();
        if (t) {
          t.status = "ok";
          t.endedAt = line.ts;
          t.durationMs = num(line["durationMs"]);
        }
        break;
      }
      case "agent failed; continuing degraded":
      case "synthesis agent failed; falling back to conservative scoring": {
        const t = current();
        if (t) {
          t.status = "failed";
          t.endedAt = line.ts;
          t.error = typeof line["error"] === "string" ? line["error"] : "error";
        }
        break;
      }
      case "vigil scan without abort": {
        const warnings = num(line["warnings"]) ?? 0;
        holder(line.ts).scans.push({
          source: str(line["source"]) ?? "?",
          at: line.ts,
          status: warnings > 0 ? "warn" : "pass",
          units: num(line["units"]),
          warnings,
          scanners: [],
        });
        break;
      }
      case "vigil detection — monitor mode, evaluation continues":
      case "vigil detection — aborting evaluation, marking Malicious": {
        const abort = line.msg.includes("aborting");
        const t = holder(line.ts);
        t.scans.push({
          source: str(line["source"]) ?? "?",
          at: line.ts,
          status: abort ? "block" : "warn",
          warnings: 0,
          confidence: num(line["confidence"]),
          scanners: strs(line["scanners"]),
        });
        if (abort) {
          t.status = "blocked";
          t.endedAt = line.ts;
        }
        break;
      }
      case "vigil unavailable — continuing in monitor mode":
        holder(line.ts).scans.push({ source: str(line["source"]) ?? "?", at: line.ts, status: "unavailable", warnings: 0, scanners: [] });
        break;
      default:
        break;
    }
  }

  if (report) enrich(trips, report);
  return trips;
}

function enrich(trips: Trip[], report: EvaluationReport): void {
  const gate = report.securityGate.vigil;
  for (const trip of trips) {
    const rec = report.agents[trip.agent];
    if (rec) {
      trip.durationMs ??= rec.durationMs;
      trip.kind ??= rec.kind;
      trip.model ??= rec.model;
      if (rec.status === "failed" && trip.status === "ok") trip.status = "failed";
      if (rec.error) trip.error ??= rec.error;
    }
    for (const scan of trip.scans) {
      scan.warningRecords = gate.warnings.filter((w) => w.source === scan.source);
      if (scan.status === "block" || scan.confidence !== undefined) {
        scan.detection = gate.detections.find((d) => d.source === scan.source);
      }
    }
  }
}

export type StationState = "idle" | "active" | "pass" | "warn" | "block" | "fail" | "off";

/** What each station shows for one trip, given the run it belongs to. */
export function stationStates(trip: Trip, trips: Trip[], run: MCPEvaluationRun | undefined): Record<StationId, StationState> {
  const s: Record<StationId, StationState> = {
    source: "pass",
    vigil: "idle",
    prompt: "idle",
    occludra: "idle",
    netbird: "idle",
    llm: "idle",
    agent: "idle",
    synthesis: "idle",
    verdict: "idle",
  };
  const scansUntrusted = trip.kind === "dynamic" || trip.kind === "adversarial" || trip.scans.length > 0;
  if (trip.scans.some((x) => x.status === "block")) s.vigil = "block";
  else if (trip.scans.some((x) => x.status === "warn" || x.status === "unavailable")) s.vigil = "warn";
  else if (trip.scans.length > 0) s.vigil = "pass";
  else if (!scansUntrusted) s.vigil = "off";
  else if (trip.status === "running") s.vigil = "active";

  const verdict = (): StationState => {
    const phase = run?.status?.phase;
    if (!isTerminal(phase)) return "idle";
    const risk = run?.status?.scoring?.riskCategory;
    if (verdictOf(risk) === "rejected") return "block";
    return phase === "Failed" ? "fail" : risk === "Caution" ? "warn" : "pass";
  };

  if (trip.status === "blocked") {
    // The runner skips the model entirely and writes Malicious to the CR itself.
    s.prompt = s.occludra = s.netbird = s.llm = s.agent = s.synthesis = "off";
    s.verdict = verdict();
    return s;
  }

  const synthesisTrip = trips.find((t) => t.kind === "synthesis");
  const synthesisState = (): StationState =>
    !synthesisTrip ? "idle" : synthesisTrip.status === "ok" ? "pass" : synthesisTrip.status === "failed" ? "fail" : "active";

  if (trip.status === "running") {
    if (s.vigil === "active") return s;
    s.prompt = s.occludra = s.netbird = "pass";
    s.llm = "active";
    return s;
  }

  s.prompt = s.occludra = s.netbird = "pass";
  if (trip.status === "failed") {
    s.llm = "fail";
    s.agent = "fail";
  } else {
    s.llm = s.agent = "pass";
  }
  s.synthesis = trip.kind === "synthesis" ? s.agent : synthesisState();
  s.verdict = verdict();
  return s;
}
