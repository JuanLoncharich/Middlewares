import type { RunPhase, Severity } from "../model/crd.ts";

export const PHASE_LABEL: Record<RunPhase, string> = {
  Pending: "En cola",
  Cloning: "Clonando",
  Running: "Sandbox arriba",
  Evaluating: "Evaluando",
  Completed: "Completado",
  Failed: "Fallido",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  Critical: "Crítico",
  High: "Alto",
  Medium: "Medio",
  Low: "Bajo",
  Info: "Info",
};

export const ROLE_LABEL: Record<string, string> = {
  StaticSecurityAuditor: "Auditor estático",
  DynamicProtocolFuzzer: "Fuzzer de protocolo",
  RogueBehaviorProbe: "Sonda de comportamiento",
  SynthesisScorer: "Síntesis",
};

/** "github.com/org/repo" without scheme or .git. */
export function shortRepo(url: string): string {
  return url.replace(/^https:\/\//, "").replace(/\.git$/, "");
}

export function relativeTime(iso: string | undefined, now = Date.now()): string {
  if (!iso) return "";
  const s = Math.round((now - Date.parse(iso)) / 1000);
  if (s < 5) return "ahora";
  if (s < 60) return `hace ${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `hace ${m} min`;
  const h = Math.round(m / 60);
  if (h < 24) return `hace ${h} h`;
  return `hace ${Math.round(h / 24)} d`;
}

export function seconds(ms: number | undefined): string {
  if (ms === undefined) return "";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function clock(iso: string | undefined): string {
  return iso ? new Date(iso).toLocaleTimeString("es-AR", { hour12: false }) : "";
}
