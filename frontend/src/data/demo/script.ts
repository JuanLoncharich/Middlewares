// A small builder for replay timelines. Every step is something the real
// system produces: a status patch the runner sends, a log line in the
// runner's format (runner/src/logger.ts), or the report it writes at the end.
import type { Finding, MCPEvaluationRunStatus, MCPServer, ScoringBlock } from "../../model/crd.ts";
import type { TripExtras } from "../../model/flow.ts";
import type { LogLevel } from "../../model/logs.ts";
import type { AgentKind, AgentRunRecord, EvaluationReport, VigilDetectionRecord, VigilWarningRecord } from "../../model/report.ts";

export type Step =
  | { at: number; kind: "status"; patch: Partial<MCPEvaluationRunStatus> }
  | { at: number; kind: "log"; level: LogLevel; component: string; msg: string; fields: Record<string, unknown> }
  | { at: number; kind: "extras"; agent: string; data: TripExtras }
  | { at: number; kind: "report" };

export interface Scenario {
  id: string;
  label: string;
  blurb: string;
  server: MCPServer;
  steps: Step[];
  durationMs: number;
  /** Fills times and names into the report the run writes at the end. */
  report(runName: string, startedAt: string, finishedAt: string): EvaluationReport;
}

export interface AgentDef {
  name: string;
  role: string;
  kind: AgentKind;
}

export const MODEL = "local/lfm2.5-24b-a2b";

export const SUITE: AgentDef[] = [
  { name: "mcp-sast-auditor", role: "StaticSecurityAuditor", kind: "static" },
  { name: "mcp-fuzz-tester", role: "DynamicProtocolFuzzer", kind: "dynamic" },
  { name: "mcp-rogue-detector", role: "RogueBehaviorProbe", kind: "adversarial" },
  { name: "mcp-synthesizer", role: "SynthesisScorer", kind: "synthesis" },
];

export interface ScanPlan {
  source: string;
  units: number;
  warnings?: VigilWarningRecord[];
  /** Milliseconds the scan takes. */
  ms: number;
}

export interface AgentPlan {
  ms: number;
  result?: unknown;
  error?: string;
  extras?: TripExtras;
  scans?: ScanPlan[];
  /** Log lines emitted while the agent works (fuzzing tool…, static evidence…). */
  notes?: { after: number; level?: LogLevel; component: string; msg: string; fields?: Record<string, unknown> }[];
}

export class Script {
  t = 0;
  readonly steps: Step[] = [];
  readonly agents: Record<string, AgentRunRecord> = {};
  readonly warnings: VigilWarningRecord[] = [];
  readonly detections: VigilDetectionRecord[] = [];
  findings: Finding[] = [];
  payloadsScanned = 0;
  private connected = false;

  constructor(readonly server: MCPServer) {}

  wait(ms: number): this {
    this.t += ms;
    return this;
  }

  status(patch: Partial<MCPEvaluationRunStatus>): this {
    this.steps.push({ at: this.t, kind: "status", patch });
    return this;
  }

  log(msg: string, fields: Record<string, unknown> = {}, level: LogLevel = "info", component = "evaluator"): this {
    this.steps.push({ at: this.t, kind: "log", level, component, msg, fields });
    return this;
  }

  /** Pending → Cloning → Running and the evaluator's start-up lines. */
  prelude(): this {
    const name = this.server.metadata.name;
    this.status({ phase: "Pending", message: "creating evaluation job" }).wait(1400);
    this.status({ phase: "Cloning", message: `cloning ${this.server.spec.repositoryUrl}@${this.server.spec.ref ?? "main"}` }).wait(5200);
    this.status({ phase: "Running", message: "sandbox containers started" }).wait(500);
    this.log("evaluator starting", {
      server: name,
      agents: SUITE.map((a) => a.name),
      transport: this.server.spec.transport ?? "stdio",
      dryRun: false,
      vigil: "http://vigil.netbird.selfhosted:5000/analyze/prompt (strict)",
      occludra: "http://occludra.netbird.selfhosted:8080/v1",
      mesh: "socks5://127.0.0.1:1080",
    });
    this.wait(300).log("waiting for mesh proxy", { proxy: "127.0.0.1:1080", waitedMs: 0 }, "info", "evaluator.mesh");
    this.wait(1100).log("mesh proxy is accepting connections", { proxy: "127.0.0.1:1080", attempt: 4 }, "info", "evaluator.mesh");
    this.wait(80).log("mesh bridge listening", { host: "127.0.0.1", port: 18080, upstream: "socks5://127.0.0.1:1080" }, "info", "evaluator.mesh");
    this.wait(20).log("mesh transport ready", { bridge: "http://127.0.0.1:18080", upstream: "socks5://127.0.0.1:1080" });
    this.wait(150).log("agents resolved", { agents: Object.fromEntries(SUITE.map((a) => [a.name, a.kind])) });
    return this.wait(300);
  }

  private scan(plan: ScanPlan): void {
    this.wait(plan.ms);
    this.payloadsScanned += plan.units;
    const warnings = plan.warnings ?? [];
    if (warnings.length > 0) {
      this.warnings.push(...warnings);
      this.findings.push({
        agent: "vigil-llm",
        severity: "Medium",
        title: `Possible prompt injection in untrusted ${plan.source} (not corroborated)`,
        description: `Vigil-LLM flagged ${warnings.length} text(s) of the MCP server's ${plan.source} with a single scanner, which on its own does not stop the evaluation.`,
        remediation: "Review the flagged texts (securityGate.vigil.warnings in the report) before integrating this server.",
      });
      this.log("vigil warnings — single-scanner hits, evaluation continues", { source: plan.source, warnings: warnings.length }, "warn");
      this.status({ findings: [...this.findings] });
    }
    this.log("vigil scan without abort", {
      source: plan.source,
      units: plan.units,
      warnings: warnings.length,
      endpoint: "http://vigil.netbird.selfhosted:5000/analyze/prompt",
    });
  }

  agent(def: AgentDef, plan: AgentPlan): this {
    const started = this.t;
    this.status({ phase: "Evaluating", currentAgent: def.name, message: `running agent ${def.name}` });
    this.log("agent start", { agent: def.name, kind: def.kind, model: MODEL });
    if (plan.extras) this.steps.push({ at: this.t, kind: "extras", agent: def.name, data: plan.extras });
    if ((def.kind === "dynamic" || def.kind === "adversarial") && !this.connected) {
      this.wait(400).log("stdio transport connected", { generation: 1 }, "info", "evaluator.stdio");
      this.connected = true;
    }
    // As in the runner: the advertised surface is scanned before fuzzing or probing starts.
    const [firstScan, ...laterScans] = plan.scans ?? [];
    if (firstScan) this.scan(firstScan);
    for (const note of plan.notes ?? []) {
      this.wait(note.after).log(note.msg, note.fields ?? {}, note.level ?? "info", note.component);
    }
    for (const scan of laterScans) this.scan(scan);
    const used = this.t - started;
    this.wait(Math.max(plan.ms - used, 500));
    const durationMs = this.t - started;
    const record: AgentRunRecord = { role: def.role, kind: def.kind, model: MODEL, durationMs, status: plan.error ? "failed" : "ok" };
    if (plan.error) {
      record.error = plan.error;
      this.log("agent failed; continuing degraded", { agent: def.name, kind: def.kind, error: plan.error }, "warn");
    } else {
      this.status({ agentResults: { [def.name]: plan.result ?? {} } });
      this.log("agent done", { agent: def.name, durationMs });
    }
    this.agents[def.name] = record;
    return this.wait(400);
  }

  /** Vigil corroborated a detection: the runner writes Malicious and stops. */
  abort(source: string, units: number, detection: Omit<VigilDetectionRecord, "source" | "abortive">, ms: number): this {
    this.wait(ms);
    this.payloadsScanned += units;
    this.detections.push({ ...detection, source, abortive: true });
    this.findings.push({
      agent: "vigil-llm",
      severity: "Critical",
      title: `Indirect prompt injection detected in untrusted ${source}`,
      description:
        `Vigil-LLM flagged the MCP server's ${source} content (${detection.segment}) as a prompt injection / jailbreak attempt ` +
        `(confidence ${detection.confidence?.toFixed(2)}); triggered scanners: ${detection.scanners.join(", ")}. Excerpt: ${detection.excerpt}`,
      remediation:
        "Do not integrate this MCP server: it embeds instructions designed to hijack LLM agents. " +
        "To triage a suspected false positive, re-run with VIGIL_ENFORCE=monitor and review the payload excerpt.",
    });
    this.log("vigil detection — aborting evaluation, marking Malicious", { source, confidence: detection.confidence, scanners: detection.scanners }, "error");
    const scoring: ScoringBlock = {
      safetyScore: 0,
      reliabilityScore: 0,
      riskCategory: "Malicious",
      summary: `Indirect prompt injection detected by Vigil-LLM in untrusted ${source}.`,
    };
    this.status({ phase: "Failed", currentAgent: "", finalScore: 0, scoring, findings: [...this.findings], message: scoring.summary });
    const running = Object.keys(this.agents).length;
    const def = SUITE[running];
    if (def) this.agents[def.name] = { role: def.role, kind: def.kind, model: MODEL, durationMs: 0, status: "failed", error: "VigilInjectionError" };
    this.wait(300).log("evaluation failed", { stage: `vigil:${source}`, errorClass: "VigilInjectionError", error: { name: "VigilInjectionError", message: `Vigil-LLM detected prompt injection in untrusted content from "${source}"` } }, "error");
    return this.finishLogs("Failed", 0, "Malicious", scoring, scoring.summary ?? "");
  }

  complete(scoring: ScoringBlock, findings: Finding[]): this {
    this.findings = [...this.findings, ...findings];
    const failed = Object.entries(this.agents).filter(([, r]) => r.status === "failed").map(([n]) => n);
    let message = `evaluated ${SUITE.length} agent(s); riskCategory=${scoring.riskCategory} finalScore=${scoring.safetyScore}`;
    if (failed.length > 0) message = `degraded: ${failed.length}/${SUITE.length} agent(s) failed (${failed.join(", ")}); ${message}`;
    this.status({ phase: "Completed", currentAgent: "", finalScore: scoring.safetyScore, scoring, findings: [...this.findings], message });
    return this.finishLogs("Completed", scoring.safetyScore, scoring.riskCategory, scoring, message);
  }

  private finishLogs(phase: "Completed" | "Failed", finalScore: number, riskCategory: string, scoring: ScoringBlock, message: string): this {
    this.wait(200).log("report written", { file: "/output/evaluation-report.json" });
    this.wait(150).log("report configmap created", { configmap: "mcp-evals/<run>-report", keys: ["report.json"] }, "info", "evaluator.k8s");
    this.steps.push({ at: this.t, kind: "report" });
    this.wait(100).log("evaluator finished", { phase, finalScore, riskCategory });
    this.final = { phase, scoring, message };
    return this;
  }

  private final: { phase: "Completed" | "Failed"; scoring: ScoringBlock; message: string } | null = null;

  build(id: string, label: string, blurb: string): Scenario {
    const final = this.final;
    if (!final) throw new Error(`scenario ${id} never finishes`);
    const snapshot = {
      agents: { ...this.agents },
      warnings: [...this.warnings],
      detections: [...this.detections],
      findings: [...this.findings],
      payloadsScanned: this.payloadsScanned,
    };
    const server = this.server;
    const degraded = Object.values(snapshot.agents).some((a) => a.status === "failed") && final.phase === "Completed";
    return {
      id,
      label,
      blurb,
      server,
      steps: this.steps,
      durationMs: this.t,
      report: (runName, startedAt, finishedAt) => ({
        runName,
        serverName: server.metadata.name,
        startedAt,
        finishedAt,
        transport: server.spec.transport ?? "stdio",
        agents: snapshot.agents,
        staticEvidenceSummary: { fileCount: 42, dependencyCount: 17, sinkCount: 6, registrationCount: 5 },
        finalScore: final.scoring.safetyScore,
        scoring: final.scoring,
        findings: snapshot.findings,
        securityGate: {
          vigil: {
            enabled: true,
            enforced: true,
            url: "http://vigil.netbird.selfhosted:5000/analyze/prompt",
            transformerThreshold: 0.98,
            payloadsScanned: snapshot.payloadsScanned,
            detections: snapshot.detections,
            warnings: snapshot.warnings,
            unavailableErrors: 0,
          },
          occludra: { enabled: true, baseUrl: "http://occludra.netbird.selfhosted:8080/v1" },
          mesh: { proxyUrl: "socks5://127.0.0.1:1080", bridgePort: 18080 },
        },
        degraded,
        phase: final.phase,
        message: final.message,
      }),
    };
  }
}
