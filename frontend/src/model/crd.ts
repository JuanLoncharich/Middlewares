// Mirrors api/v1alpha1/*_types.go (JSON field names) so live objects from the
// API server and demo fixtures share one shape. Keep in sync with the Go types
// and runner/src/types.ts.

export const API_VERSION = "security.eval.io/v1alpha1";

/** Label the operator puts on every Job/Pod of a run (api/v1alpha1/groupversion_info.go). */
export const LABEL_RUN = "security.eval.io/run";

export interface ObjectMeta {
  name: string;
  namespace?: string;
  uid?: string;
  resourceVersion?: string;
  creationTimestamp?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface Condition {
  type: string;
  status: "True" | "False" | "Unknown";
  reason?: string;
  message?: string;
  lastTransitionTime?: string;
}

// --- MCPServer --------------------------------------------------------------

export type Transport = "stdio" | "sse";

export interface MCPServerSpec {
  repositoryUrl: string;
  ref?: string;
  path?: string;
  transport?: Transport;
  targetPort?: number;
  schedule: string;
  active?: boolean;
  credentialsSecretRef?: string;
  agentSuite: { name: string }[];
  timeoutSeconds?: number;
  runHistoryLimit?: number;
}

export interface MCPServerStatus {
  lastEvaluationDate?: string;
  nextScheduledTime?: string;
  overallRiskStatus?: string;
  lastRunRef?: string;
  lastFinalScore?: number;
  conditions?: Condition[];
}

export interface MCPServer {
  apiVersion: string;
  kind: "MCPServer";
  metadata: ObjectMeta;
  spec: MCPServerSpec;
  status?: MCPServerStatus;
}

// --- MCPEvaluationRun -------------------------------------------------------

export type RunPhase = "Pending" | "Cloning" | "Running" | "Evaluating" | "Completed" | "Failed";
export const RUN_PHASES: RunPhase[] = ["Pending", "Cloning", "Running", "Evaluating", "Completed", "Failed"];

export type RiskCategory = "Safe" | "Caution" | "Untrusted" | "Malicious" | "Unknown";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface ScoringBlock {
  safetyScore: number;
  reliabilityScore: number;
  riskCategory: RiskCategory;
  summary?: string;
}

export interface Finding {
  agent: string;
  severity: Severity;
  title: string;
  description?: string;
  remediation?: string;
}

export interface MCPEvaluationRunSpec {
  serverRef: string;
  agents: string[];
  timeoutSeconds?: number;
}

export interface MCPEvaluationRunStatus {
  phase?: RunPhase;
  currentAgent?: string;
  agentResults?: Record<string, unknown>;
  finalScore?: number;
  scoring?: ScoringBlock;
  findings?: Finding[];
  message?: string;
  jobName?: string;
  retries?: number;
  startTime?: string;
  completionTime?: string;
  conditions?: Condition[];
}

export interface MCPEvaluationRun {
  apiVersion: string;
  kind: "MCPEvaluationRun";
  metadata: ObjectMeta;
  spec: MCPEvaluationRunSpec;
  status?: MCPEvaluationRunStatus;
}

// --- OpenCodeAgent ----------------------------------------------------------

export type AgentRole = "StaticSecurityAuditor" | "DynamicProtocolFuzzer" | "RogueBehaviorProbe" | "SynthesisScorer";

export interface OpenCodeAgent {
  apiVersion: string;
  kind: "OpenCodeAgent";
  metadata: ObjectMeta;
  spec: {
    role: string;
    model: { providerID: string; modelID: string; contextTokens?: number };
    config?: { timeoutMs?: number; retryCount?: number };
    systemPrompt: string;
    outputFormat: { type: "json_schema"; schema: unknown };
  };
}

// --- helpers ----------------------------------------------------------------

export function isTerminal(phase: RunPhase | undefined): boolean {
  return phase === "Completed" || phase === "Failed";
}

/** Which board column a server belongs to. */
export type Verdict = "evaluating" | "approved" | "rejected" | "unknown";

export function verdictOf(risk: string | undefined): Verdict {
  if (risk === "Safe" || risk === "Caution") return "approved";
  if (risk === "Untrusted" || risk === "Malicious") return "rejected";
  return "unknown";
}

const SEVERITY_ORDER: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
}
