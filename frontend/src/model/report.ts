// The subset of runner/src/types.ts EvaluationReport the UI reads. The live
// backend takes it from the `<run>-report` ConfigMap (key report.json), which
// the evaluator writes when the run ends.
import type { Finding, RiskCategory, RunPhase, ScoringBlock, Transport } from "./crd.ts";

export type AgentKind = "static" | "dynamic" | "adversarial" | "synthesis" | "generic";

export interface AgentRunRecord {
  role: string;
  kind: AgentKind;
  model: string;
  durationMs: number;
  status: "ok" | "failed";
  error?: string;
}

export interface VigilScannerHit {
  scanner: string;
  score?: number;
  detail?: string;
}

export interface VigilDetectionRecord {
  source: string;
  segment?: string;
  confidence?: number;
  scanners: string[];
  excerpt: string;
  abortive: boolean;
}

export interface VigilWarningRecord {
  source: string;
  segment: string;
  scanners: string[];
  hits: VigilScannerHit[];
  excerpt: string;
}

export interface SecurityGateReport {
  vigil: {
    enabled: boolean;
    enforced: boolean;
    url: string;
    transformerThreshold: number;
    payloadsScanned: number;
    detections: VigilDetectionRecord[];
    warnings: VigilWarningRecord[];
    unavailableErrors: number;
  };
  occludra: { enabled: boolean; baseUrl: string };
  mesh: { proxyUrl: string | null; bridgePort: number | null };
}

export interface EvaluationReport {
  runName: string;
  serverName: string;
  startedAt: string;
  finishedAt: string;
  transport: Transport;
  agents: Record<string, AgentRunRecord>;
  staticEvidenceSummary: {
    fileCount: number;
    dependencyCount: number;
    sinkCount: number;
    registrationCount: number;
  } | null;
  finalScore: number;
  scoring: ScoringBlock;
  findings: Finding[];
  securityGate: SecurityGateReport;
  degraded?: boolean;
  phase: RunPhase;
  message: string;
}

/** Runner role → agent kind, as runner/src/evaluator.ts resolves them. */
export function kindOfRole(role: string): AgentKind {
  switch (role) {
    case "StaticSecurityAuditor":
      return "static";
    case "DynamicProtocolFuzzer":
      return "dynamic";
    case "RogueBehaviorProbe":
      return "adversarial";
    case "SynthesisScorer":
      return "synthesis";
    default:
      return "generic";
  }
}

export const RISK_LABEL: Record<RiskCategory, string> = {
  Safe: "Seguro",
  Caution: "Precaución",
  Untrusted: "No confiable",
  Malicious: "Malicioso",
  Unknown: "Sin veredicto",
};
