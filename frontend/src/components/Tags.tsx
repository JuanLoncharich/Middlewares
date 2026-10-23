import type { RiskCategory, RunPhase, Severity } from "../model/crd.ts";
import { RISK_LABEL } from "../model/report.ts";
import { PHASE_LABEL, SEVERITY_LABEL } from "./format.ts";

export function RiskTag({ risk }: { risk: string | undefined }) {
  const r = (risk && risk in RISK_LABEL ? risk : "Unknown") as RiskCategory;
  return <span className={`tag tag-risk-${r.toLowerCase()}`}>{RISK_LABEL[r]}</span>;
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return <span className={`tag tag-sev-${severity.toLowerCase()}`}>{SEVERITY_LABEL[severity]}</span>;
}

export function PhaseTag({ phase }: { phase: RunPhase | undefined }) {
  const p = phase ?? "Pending";
  return <span className={`tag tag-phase-${p.toLowerCase()}`}>{PHASE_LABEL[p]}</span>;
}
