/**
 * Shared type definitions for the MCP evaluation runner.
 *
 * These mirror the security.eval.io/v1alpha1 CRDs (OpenCodeAgent, MCPServer,
 * MCPEvaluationRun) and define the JSON-RPC, telemetry, fuzzing, probing and
 * report shapes used by every module in the runner.
 */

// ---------------------------------------------------------------------------
// Kubernetes CR shapes
// ---------------------------------------------------------------------------

export const API_GROUP = "security.eval.io";
export const API_VERSION = "v1alpha1";
export const PLURAL_AGENTS = "opencodeagents";
export const PLURAL_SERVERS = "mcpservers";
export const PLURAL_RUNS = "mcpevaluationruns";

export interface ObjectMeta {
  name: string;
  namespace?: string;
  uid?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface JsonSchema {
  [key: string]: unknown;
}

export interface OpenCodeAgentModel {
  providerID: string;
  modelID: string;
}

export interface OpenCodeAgentConfig {
  timeoutMs?: number;
  retryCount?: number;
}

export interface OpenCodeAgentOutputFormat {
  type: "json_schema";
  schema: JsonSchema;
}

export interface OpenCodeAgentSpec {
  role: string;
  model: OpenCodeAgentModel;
  config?: OpenCodeAgentConfig;
  systemPrompt: string;
  outputFormat: OpenCodeAgentOutputFormat;
}

export interface OpenCodeAgent {
  apiVersion: string;
  kind: "OpenCodeAgent";
  metadata: ObjectMeta;
  spec: OpenCodeAgentSpec;
}

export type Transport = "stdio" | "sse";

export interface AgentReference {
  name: string;
}

export interface MCPServerSpec {
  repositoryUrl: string;
  ref: string;
  path?: string;
  transport: Transport;
  targetPort?: number;
  schedule: string;
  active: boolean;
  credentialsSecretRef?: string;
  agentSuite: AgentReference[];
  timeoutSeconds?: number;
}

export interface MCPServer {
  apiVersion: string;
  kind: "MCPServer";
  metadata: ObjectMeta;
  spec: MCPServerSpec;
}

export type RunPhase =
  | "Pending"
  | "Cloning"
  | "Running"
  | "Evaluating"
  | "Completed"
  | "Failed";

export type RiskCategory = "Safe" | "Caution" | "Untrusted" | "Malicious" | "Unknown";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface ScoringBlock {
  safetyScore: number;
  reliabilityScore: number;
  riskCategory: RiskCategory;
  summary: string;
}

export interface Finding {
  agent: string;
  severity: Severity;
  title: string;
  description: string;
  remediation?: string;
}

export interface MCPEvaluationRunStatus {
  phase: RunPhase;
  currentAgent: string;
  agentResults: Record<string, unknown>;
  finalScore: number;
  scoring: ScoringBlock;
  findings: Finding[];
  message: string;
}

// ---------------------------------------------------------------------------
// Runner environment
// ---------------------------------------------------------------------------

export interface RunnerEnv {
  runName: string;
  runNamespace: string;
  serverName: string;
  agentNames: string[];
  transport: Transport;
  targetPort: number;
  workspaceDir: string;
  ipcDir: string;
  outputDir: string;
  opencodePort: number;
  dryRun: boolean;

  // --- security layer: Vigil-LLM (inbound prompt-injection scanner) ---
  /** Full URL of the Vigil /analyze endpoint (routed over the NetBird mesh). */
  vigilUrl: string;
  /** Hard gate (true) or observe-only (false). */
  vigilEnabled: boolean;
  /** strict: scanner failure or detection fails the run; monitor: log only. */
  vigilEnforce: boolean;
  /** Per-request timeout and payload truncation ceiling for scans. */
  vigilTimeoutMs: number;
  vigilMaxPayloadBytes: number;

  // --- security layer: Occludra (outgoing LLM gateway) ---
  /** OpenAI-compatible base URL the OpenCode providers are pointed at. */
  occludraBaseUrl: string;
  /** false restores direct provider calls (dev only — breaks mesh isolation). */
  occludraEnabled: boolean;

  // --- security layer: NetBird mesh transport ---
  /** socks5://127.0.0.1:1080 (NetBird userspace sidecar) or null to disable. */
  meshProxyUrl: string | null;
  /** Local HTTP-proxy bridge port for the OpenCode child process. */
  meshBridgePort: number;
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 / MCP shapes
// ---------------------------------------------------------------------------

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: JsonRpcError;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: JsonSchema;
  annotations?: Record<string, unknown>;
}

export interface McpPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface McpPromptDefinition {
  name: string;
  description?: string;
  arguments?: McpPromptArgument[];
}

export interface McpResourceDefinition {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface McpInitializeResult {
  protocolVersion: string;
  capabilities: Record<string, unknown>;
  serverInfo?: { name?: string; version?: string };
  instructions?: string;
}

export interface McpContentBlock {
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface McpToolCallResult {
  content?: McpContentBlock[];
  isError?: boolean;
  structuredContent?: unknown;
  [key: string]: unknown;
}

/** Outcome of a single request with hang/crash/malformed awareness. */
export interface RpcOutcome {
  ok: boolean;
  result?: unknown;
  error?: JsonRpcError;
  hang: boolean;
  crashed: boolean;
  latencyMs: number;
  transportError?: string;
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

export interface LatencyStats {
  count: number;
  avgMs: number;
  p95Ms: number;
  maxMs: number;
  minMs: number;
}

export interface Telemetry {
  initializeOk: boolean;
  protocolVersion: string;
  serverInfo: { name?: string; version?: string };
  toolsCount: number;
  promptsCount: number;
  resourcesCount: number;
  fuzzCases: number;
  crashes: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  maxLatencyMs: number;
  hangs: number;
  malformedFrames: number;
  unsolicitedRequests: number;
  notifications: number;
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

export type FuzzCategory =
  | "boundary"
  | "type-mismatch"
  | "null-required"
  | "missing-required"
  | "extra-props"
  | "prototype-pollution"
  | "path-traversal"
  | "command-injection"
  | "unicode"
  | "oversize"
  | "deep-nesting"
  | "protocol";

export interface FuzzCase {
  id: string;
  tool: string;
  category: FuzzCategory;
  description: string;
  /** Tool arguments (for tool-level cases). */
  args?: unknown;
  /** Raw frame text (for protocol-level cases). */
  rawFrame?: string;
}

export type FuzzErrorClass =
  | "ok"
  | "jsonrpc-error"
  | "tool-error"
  | "hang"
  | "crash"
  | "transport-error"
  | "malformed-response";

export interface FuzzCaseResult {
  caseId: string;
  tool: string;
  category: FuzzCategory;
  description: string;
  errorClass: FuzzErrorClass;
  latencyMs: number;
  errorCode?: number;
  errorMessage?: string;
  responseExcerpt?: string;
}

export interface NotableResponse {
  caseId: string;
  tool: string;
  reason: string;
  excerpt: string;
}

export interface FuzzReport {
  cases: FuzzCaseResult[];
  totalCases: number;
  crashes: number;
  hangs: number;
  errorsByClass: Record<FuzzErrorClass, number>;
  latency: LatencyStats;
  notableResponses: NotableResponse[];
  timeBudgetExhausted: boolean;
}

// ---------------------------------------------------------------------------
// Adversarial probes
// ---------------------------------------------------------------------------

export type DetectorFlag =
  | "injection-marker"
  | "hidden-instruction"
  | "base64-instruction"
  | "zero-width-chars"
  | "exfil-marker"
  | "ssrf-indicator"
  | "host-file-read"
  | "env-leak"
  | "absolute-path-leak";

export interface DetectorHit {
  flag: DetectorFlag;
  pattern: string;
  excerpt: string;
}

export interface ToolProbeResult {
  tool: string;
  argsUsed: unknown;
  ok: boolean;
  isError: boolean;
  latencyMs: number;
  hang: boolean;
  crashed: boolean;
  outputExcerpt: string;
  hits: DetectorHit[];
}

export interface ActiveProbeResult {
  tool: string;
  parameter: string;
  payload: string;
  kind: "ssrf" | "host-file-read" | "path-traversal";
  ok: boolean;
  succeeded: boolean;
  latencyMs: number;
  evidence: string;
}

export interface ProbeReport {
  benignCalls: ToolProbeResult[];
  activeProbes: ActiveProbeResult[];
  unsolicitedRequests: { method: string; count: number }[];
  notificationsCount: number;
  serverInstructionsHits: DetectorHit[];
  toolDescriptionHits: { tool: string; hits: DetectorHit[] }[];
  flags: {
    promptInjectionDetected: boolean;
    exfiltrationAttemptDetected: boolean;
    ssrfPossible: boolean;
    hostFileReadPossible: boolean;
    unsolicitedServerRequests: boolean;
    silentSecondaryActions: boolean;
  };
}

// ---------------------------------------------------------------------------
// Static evidence
// ---------------------------------------------------------------------------

export interface ManifestFile {
  path: string;
  content: string;
  truncated: boolean;
}

export interface DependencyEntry {
  ecosystem: "npm" | "pypi" | "go" | "cargo";
  name: string;
  version: string;
  source: string;
}

export interface SinkHit {
  file: string;
  line: number;
  pattern: string;
  category: string;
  snippet: string;
}

export interface RegistrationHit {
  file: string;
  line: number;
  pattern: string;
  snippet: string;
}

export interface StaticEvidence {
  runtime: string;
  fileCount: number;
  filesSampled: string[];
  manifests: ManifestFile[];
  dependencies: DependencyEntry[];
  registrations: RegistrationHit[];
  sinks: SinkHit[];
  launchFile: unknown;
  truncated: boolean;
  totalBytes: number;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export type AgentKind = "static" | "dynamic" | "adversarial" | "synthesis" | "generic";

export interface AgentRunRecord {
  role: string;
  kind: AgentKind;
  model: string;
  durationMs: number;
  status: "ok" | "failed";
  error?: string;
  structuredOutput?: unknown;
}

export interface VigilDetectionRecord {
  source: string;
  confidence?: number;
  scanners: string[];
  excerpt: string;
  abortive: boolean;
}

export interface SecurityGateReport {
  vigil: {
    enabled: boolean;
    enforced: boolean;
    url: string;
    payloadsScanned: number;
    detections: VigilDetectionRecord[];
    unavailableErrors: number;
  };
  occludra: {
    enabled: boolean;
    baseUrl: string;
  };
  mesh: {
    proxyUrl: string | null;
    bridgePort: number | null;
  };
}

export interface EvaluationReport {
  runName: string;
  serverName: string;
  startedAt: string;
  finishedAt: string;
  transport: Transport;
  agents: Record<string, AgentRunRecord>;
  telemetry: Telemetry;
  probes: ProbeReport | null;
  fuzz: FuzzReport | null;
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
  phase: RunPhase;
  message: string;
}

export interface TerminationMessage {
  phase: RunPhase;
  finalScore: number;
  riskCategory: RiskCategory;
  message: string;
}

// ---------------------------------------------------------------------------
// Synthesis output (lenient)
// ---------------------------------------------------------------------------

export interface RemediationItem {
  title: string;
  severity: Severity;
  description: string;
  codeGuidance: string;
}

export interface SynthesisOutput {
  safetyScore: number;
  reliabilityScore: number;
  riskCategory: RiskCategory;
  summary: string;
  remediationPlan: RemediationItem[];
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

export class RunnerError extends Error {
  public readonly stage: string;
  constructor(name: string, stage: string, message: string) {
    super(message);
    this.name = name;
    this.stage = stage;
  }
}

export class AgentTimeoutError extends RunnerError {
  public readonly agent: string;
  public readonly timeoutMs: number;
  constructor(agent: string, timeoutMs: number) {
    super("AgentTimeoutError", `agent:${agent}`, `agent "${agent}" exceeded timeout of ${timeoutMs}ms`);
    this.agent = agent;
    this.timeoutMs = timeoutMs;
  }
}

export class StructuredOutputExhaustedError extends RunnerError {
  public readonly agent: string;
  public readonly retries: number;
  constructor(agent: string, retries: number, detail: string) {
    super(
      "StructuredOutputExhaustedError",
      `agent:${agent}`,
      `agent "${agent}" failed to produce schema-conformant output after ${retries} retries: ${detail}`,
    );
    this.agent = agent;
    this.retries = retries;
  }
}

export class TargetCrashError extends RunnerError {
  constructor(detail: string) {
    super("TargetCrashError", "target", `target MCP server crashed: ${detail}`);
  }
}

export class MalformedFrameError extends RunnerError {
  public readonly raw: string;
  constructor(raw: string, detail: string) {
    super("MalformedFrameError", "target", `malformed JSON-RPC frame from target: ${detail}`);
    this.raw = raw;
  }
}

export class TargetUnavailableError extends RunnerError {
  constructor(detail: string) {
    super("TargetUnavailableError", "target", `target MCP server unavailable: ${detail}`);
  }
}

export class AgentPromptError extends RunnerError {
  public readonly agent: string;
  constructor(agent: string, detail: string) {
    super("AgentPromptError", `agent:${agent}`, `agent "${agent}" prompt failed: ${detail}`);
    this.agent = agent;
  }
}

export class ConfigurationError extends RunnerError {
  constructor(detail: string) {
    super("ConfigurationError", "config", detail);
  }
}

/** Raised when Vigil-LLM flags a payload as prompt injection / jailbreak. */
export class VigilInjectionError extends RunnerError {
  public readonly source: string;
  public readonly confidence?: number;
  public readonly scanners: string[];
  public readonly excerpt: string;
  constructor(source: string, confidence: number | undefined, scanners: string[], excerpt: string) {
    super(
      "VigilInjectionError",
      `vigil:${source}`,
      `Vigil-LLM detected prompt injection in untrusted content from "${source}"` +
        (scanners.length > 0 ? ` (scanners: ${scanners.join(", ")})` : "") +
        (confidence !== undefined ? ` confidence=${confidence.toFixed(2)}` : "") +
        ` — excerpt: ${excerpt}`,
    );
    this.source = source;
    this.confidence = confidence;
    this.scanners = scanners;
    this.excerpt = excerpt;
  }
}

/** Raised when the Vigil-LLM API could not be reached or answered uselessly. */
export class VigilUnavailableError extends RunnerError {
  public readonly source: string;
  constructor(source: string, detail: string) {
    super("VigilUnavailableError", `vigil:${source}`, `Vigil-LLM scan failed for "${source}": ${detail}`);
    this.source = source;
  }
}

/** Raised when a request through the NetBird mesh proxy fails. */
export class MeshTransportError extends RunnerError {
  constructor(detail: string) {
    super("MeshTransportError", "mesh", `mesh transport failure: ${detail}`);
  }
}

// ---------------------------------------------------------------------------
// Type guards / validators
// ---------------------------------------------------------------------------

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

const RISK_CATEGORIES: readonly RiskCategory[] = ["Safe", "Caution", "Untrusted", "Malicious", "Unknown"];
const SEVERITIES: readonly Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export function isRiskCategory(value: unknown): value is RiskCategory {
  return typeof value === "string" && (RISK_CATEGORIES as readonly string[]).includes(value);
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

export function assertOpenCodeAgent(obj: unknown): OpenCodeAgent {
  if (!isRecord(obj)) {
    throw new ConfigurationError("OpenCodeAgent object is not an object");
  }
  const metadata = obj["metadata"];
  if (!isRecord(metadata) || !isNonEmptyString(metadata["name"])) {
    throw new ConfigurationError("OpenCodeAgent.metadata.name is missing");
  }
  const name = metadata["name"];
  const spec = obj["spec"];
  if (!isRecord(spec)) {
    throw new ConfigurationError(`OpenCodeAgent ${name}: spec is missing`);
  }
  if (!isNonEmptyString(spec["role"])) {
    throw new ConfigurationError(`OpenCodeAgent ${name}: spec.role is required`);
  }
  const model = spec["model"];
  if (!isRecord(model) || !isNonEmptyString(model["providerID"]) || !isNonEmptyString(model["modelID"])) {
    throw new ConfigurationError(`OpenCodeAgent ${name}: spec.model.providerID and spec.model.modelID are required`);
  }
  if (!isNonEmptyString(spec["systemPrompt"])) {
    throw new ConfigurationError(`OpenCodeAgent ${name}: spec.systemPrompt is required`);
  }
  const outputFormat = spec["outputFormat"];
  if (!isRecord(outputFormat) || outputFormat["type"] !== "json_schema" || !isRecord(outputFormat["schema"])) {
    throw new ConfigurationError(
      `OpenCodeAgent ${name}: spec.outputFormat must be { type: "json_schema", schema: <object> }`,
    );
  }
  const rawConfig = spec["config"];
  const config: OpenCodeAgentConfig = {};
  if (isRecord(rawConfig)) {
    if (rawConfig["timeoutMs"] !== undefined) {
      if (!isFiniteNumber(rawConfig["timeoutMs"]) || rawConfig["timeoutMs"] <= 0) {
        throw new ConfigurationError(`OpenCodeAgent ${name}: spec.config.timeoutMs must be a positive number`);
      }
      config.timeoutMs = rawConfig["timeoutMs"];
    }
    if (rawConfig["retryCount"] !== undefined) {
      if (!isFiniteNumber(rawConfig["retryCount"]) || rawConfig["retryCount"] < 0) {
        throw new ConfigurationError(`OpenCodeAgent ${name}: spec.config.retryCount must be a non-negative number`);
      }
      config.retryCount = Math.floor(rawConfig["retryCount"]);
    }
  }
  const labels = isRecord(metadata["labels"]) ? stringRecord(metadata["labels"]) : undefined;
  const annotations = isRecord(metadata["annotations"]) ? stringRecord(metadata["annotations"]) : undefined;
  return {
    apiVersion: typeof obj["apiVersion"] === "string" ? obj["apiVersion"] : `${API_GROUP}/${API_VERSION}`,
    kind: "OpenCodeAgent",
    metadata: {
      name,
      namespace: typeof metadata["namespace"] === "string" ? metadata["namespace"] : undefined,
      uid: typeof metadata["uid"] === "string" ? metadata["uid"] : undefined,
      labels,
      annotations,
    },
    spec: {
      role: spec["role"],
      model: { providerID: model["providerID"], modelID: model["modelID"] },
      config,
      systemPrompt: spec["systemPrompt"],
      outputFormat: { type: "json_schema", schema: outputFormat["schema"] },
    },
  };
}

export function assertMCPServer(obj: unknown): MCPServer {
  if (!isRecord(obj)) {
    throw new ConfigurationError("MCPServer object is not an object");
  }
  const metadata = obj["metadata"];
  if (!isRecord(metadata) || !isNonEmptyString(metadata["name"])) {
    throw new ConfigurationError("MCPServer.metadata.name is missing");
  }
  const name = metadata["name"];
  const spec = obj["spec"];
  if (!isRecord(spec)) {
    throw new ConfigurationError(`MCPServer ${name}: spec is missing`);
  }
  if (!isNonEmptyString(spec["repositoryUrl"])) {
    throw new ConfigurationError(`MCPServer ${name}: spec.repositoryUrl is required`);
  }
  const transport = spec["transport"];
  if (transport !== undefined && transport !== "stdio" && transport !== "sse") {
    throw new ConfigurationError(`MCPServer ${name}: spec.transport must be "stdio" or "sse"`);
  }
  const rawSuite = spec["agentSuite"];
  const agentSuite: AgentReference[] = [];
  if (Array.isArray(rawSuite)) {
    for (const entry of rawSuite) {
      if (isRecord(entry) && isNonEmptyString(entry["name"])) {
        agentSuite.push({ name: entry["name"] });
      }
    }
  }
  return {
    apiVersion: typeof obj["apiVersion"] === "string" ? obj["apiVersion"] : `${API_GROUP}/${API_VERSION}`,
    kind: "MCPServer",
    metadata: {
      name,
      namespace: typeof metadata["namespace"] === "string" ? metadata["namespace"] : undefined,
      uid: typeof metadata["uid"] === "string" ? metadata["uid"] : undefined,
    },
    spec: {
      repositoryUrl: spec["repositoryUrl"],
      ref: isNonEmptyString(spec["ref"]) ? spec["ref"] : "main",
      path: isNonEmptyString(spec["path"]) ? spec["path"] : undefined,
      transport: transport === "sse" ? "sse" : "stdio",
      targetPort: isFiniteNumber(spec["targetPort"]) ? spec["targetPort"] : 8080,
      schedule: typeof spec["schedule"] === "string" ? spec["schedule"] : "",
      active: spec["active"] !== false,
      credentialsSecretRef: isNonEmptyString(spec["credentialsSecretRef"]) ? spec["credentialsSecretRef"] : undefined,
      agentSuite,
      timeoutSeconds: isFiniteNumber(spec["timeoutSeconds"]) ? spec["timeoutSeconds"] : undefined,
    },
  };
}

function stringRecord(input: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(input)) {
    if (typeof v === "string") {
      out[k] = v;
    }
  }
  return out;
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`;
  }
  if (typeof err === "string") {
    return err;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

export function errorName(err: unknown): string {
  if (err instanceof Error) {
    return err.name;
  }
  return "UnknownError";
}

export function emptyScoring(): ScoringBlock {
  return { safetyScore: 0, reliabilityScore: 0, riskCategory: "Unknown", summary: "" };
}

export function emptyTelemetry(): Telemetry {
  return {
    initializeOk: false,
    protocolVersion: "",
    serverInfo: {},
    toolsCount: 0,
    promptsCount: 0,
    resourcesCount: 0,
    fuzzCases: 0,
    crashes: 0,
    avgLatencyMs: 0,
    p95LatencyMs: 0,
    maxLatencyMs: 0,
    hangs: 0,
    malformedFrames: 0,
    unsolicitedRequests: 0,
    notifications: 0,
  };
}
