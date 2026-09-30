/**
 * Kubernetes access for the runner: fetches OpenCodeAgent / MCPServer CRs,
 * patches MCPEvaluationRun status via the status subresource, and persists
 * the final evaluation report into an owner-referenced ConfigMap so it
 * survives the evaluation pod's ttlSecondsAfterFinished.
 *
 * In DRY_RUN mode (env DRY_RUN=1) no API server is contacted: agents are read
 * from `${OUTPUT_DIR}/agents/<name>.json` (or `${OUTPUT_DIR}/agents/*.json`),
 * the server from `${OUTPUT_DIR}/server.json`, and patches are printed.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as k8s from "@kubernetes/client-node";
import { Logger, rootLogger } from "./logger.js";
import {
  API_GROUP,
  API_VERSION,
  ConfigurationError,
  EvaluationReport,
  MCPEvaluationRunStatus,
  MCPServer,
  OpenCodeAgent,
  PLURAL_AGENTS,
  PLURAL_RUNS,
  PLURAL_SERVERS,
  assertMCPServer,
  assertOpenCodeAgent,
  errorMessage,
  isNonEmptyString,
  isRecord,
} from "./types.js";

export interface StatusWriter {
  fetchAgent(name: string): Promise<OpenCodeAgent>;
  fetchServer(name: string): Promise<MCPServer>;
  patchStatus(partial: Partial<MCPEvaluationRunStatus>): Promise<void>;
  /**
   * Last-chance re-attempt of a terminal-phase patch that was abandoned by
   * patchStatus after its retries. Called once from the shutdown path so a
   * lost "Completed"/"Failed" write does not strand the CR non-terminally.
   * Best-effort; never throws.
   */
  flushTerminalPatch(): Promise<void>;
  /**
   * Persist the final evaluation report into a ConfigMap named
   * `<run-name>-report` in the run's namespace, owner-referenced to the
   * MCPEvaluationRun (garbage-collected with it), so the full report
   * survives the Job pod's ttlSecondsAfterFinished. Oversized reports are
   * stored as a compact summary plus a truncated prefix. Best-effort; never
   * throws.
   */
  persistReport(report: EvaluationReport): Promise<void>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const RETRY_DELAYS = [500, 1500, 4000];
const TERMINAL_RETRY_DELAYS = [500, 1500, 4000, 8000, 8000];
const FETCH_RETRY_DELAYS = [500, 1500, 3000];

// --- report ConfigMap size policy -------------------------------------------
// A ConfigMap's total payload is limited to ~1MiB; stay safely below it.
const REPORT_CONFIGMAP_MAX_BYTES = 900 * 1024;
/** Byte ceiling for the truncated full-report fallback key. */
const TRUNCATED_REPORT_BYTES = 800 * 1024;
/** Findings kept in the compact summary when the full report is oversized. */
const SUMMARY_MAX_FINDINGS = 20;

/** UTF-8-safe byte-prefix cut; pretty-printed JSON is cut at a line boundary. */
function truncateUtf8(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, "utf8");
  if (buf.byteLength <= maxBytes) {
    return text;
  }
  const cut = buf.subarray(0, maxBytes).toString("utf8");
  const lastNewline = cut.lastIndexOf("\n");
  return lastNewline > 0 ? cut.slice(0, lastNewline) : cut;
}

/** Hard character cap for free-text fields in the compact summary. */
const SUMMARY_TEXT_CAP = 2048;

function clip(text: string, max = SUMMARY_TEXT_CAP): string {
  return text.length <= max ? text : `${text.slice(0, max)}…`;
}

/**
 * ConfigMap `data` for the report. If the exact pretty-printed report fits
 * under the size ceiling it is stored verbatim under `report.json`;
 * otherwise an honest smaller fallback is stored instead: a compact
 * `summary.json` (finalScore, riskCategory, per-agent status/error, findings
 * count + first N findings) plus `report.truncated.json`, a deterministic
 * ~800KiB prefix of the full JSON (line-aligned, not valid JSON by design).
 */
function reportConfigMapData(report: EvaluationReport, reportJson: string): Record<string, string> {
  if (Buffer.byteLength(reportJson, "utf8") <= REPORT_CONFIGMAP_MAX_BYTES) {
    return { "report.json": reportJson };
  }
  const summary = {
    note: "report.json exceeded the ConfigMap size limit; see report.truncated.json for the first ~800KiB of the full JSON",
    runName: report.runName,
    serverName: report.serverName,
    startedAt: report.startedAt,
    finishedAt: report.finishedAt,
    phase: report.phase,
    degraded: report.degraded === true,
    message: clip(report.message),
    finalScore: report.finalScore,
    scoring: { ...report.scoring, summary: clip(report.scoring.summary) },
    agents: Object.fromEntries(
      Object.entries(report.agents).map(([name, rec]) => [
        name,
        { status: rec.status, error: rec.error === undefined ? undefined : clip(rec.error) },
      ]),
    ),
    findingsCount: report.findings.length,
    findings: report.findings.slice(0, SUMMARY_MAX_FINDINGS).map((f) => ({
      agent: f.agent,
      severity: f.severity,
      title: clip(f.title, 512),
      description: clip(f.description),
      remediation: f.remediation === undefined ? undefined : clip(f.remediation),
    })),
    findingsTruncated: report.findings.length > SUMMARY_MAX_FINDINGS,
  };
  return {
    "summary.json": JSON.stringify(summary, null, 2),
    "report.truncated.json": truncateUtf8(reportJson, TRUNCATED_REPORT_BYTES),
  };
}

function httpStatusCode(err: unknown): number | undefined {
  if (typeof err === "object" && err !== null && "statusCode" in err) {
    const code = (err as { statusCode?: unknown }).statusCode;
    if (typeof code === "number") return code;
  }
  return undefined;
}

export class K8sStatusWriter implements StatusWriter {
  private readonly namespace: string;
  private readonly runName: string;
  private readonly api: k8s.CustomObjectsApi;
  private readonly core: k8s.CoreV1Api;
  private readonly log: Logger;
  private pendingTerminalPatch: Partial<MCPEvaluationRunStatus> | null = null;

  constructor(namespace: string, runName: string) {
    this.namespace = namespace;
    this.runName = runName;
    this.log = rootLogger.child("k8s");
    const kc = new k8s.KubeConfig();
    try {
      kc.loadFromDefault();
    } catch (err) {
      throw new ConfigurationError(`unable to load kubeconfig / in-cluster config: ${errorMessage(err)}`);
    }
    this.api = kc.makeApiClient(k8s.CustomObjectsApi);
    this.core = kc.makeApiClient(k8s.CoreV1Api);
  }

  async fetchAgent(name: string): Promise<OpenCodeAgent> {
    const raw = await this.getWithRetry(
      (name2) =>
        this.api.getNamespacedCustomObject({
          group: API_GROUP,
          version: API_VERSION,
          namespace: this.namespace,
          plural: PLURAL_AGENTS,
          name: name2,
        }),
      `OpenCodeAgent ${this.namespace}/${name}`,
      name,
    );
    return assertOpenCodeAgent(raw);
  }

  async fetchServer(name: string): Promise<MCPServer> {
    const raw = await this.getWithRetry(
      (name2) =>
        this.api.getNamespacedCustomObject({
          group: API_GROUP,
          version: API_VERSION,
          namespace: this.namespace,
          plural: PLURAL_SERVERS,
          name: name2,
        }),
      `MCPServer ${this.namespace}/${name}`,
      name,
    );
    return assertMCPServer(raw);
  }

  /**
   * GET with retries for transient API-server failures. A 404 is permanent
   * (the CR genuinely does not exist) and fails fast; anything else gets
   * FETCH_RETRY_DELAYS attempts before the caller sees the error.
   */
  private async getWithRetry(
    get: (name: string) => Promise<unknown>,
    label: string,
    name: string,
  ): Promise<unknown> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await get(name);
      } catch (err) {
        if (httpStatusCode(err) === 404) {
          throw new ConfigurationError(`failed to fetch ${label}: not found`);
        }
        const delay = FETCH_RETRY_DELAYS[attempt];
        if (delay === undefined) {
          throw new ConfigurationError(`failed to fetch ${label}: ${errorMessage(err)}`);
        }
        this.log.warn("fetch failed; retrying", { label, attempt: attempt + 1, error: errorMessage(err) });
        await sleep(delay);
      }
    }
  }

  /**
   * Merge-patches the status subresource. Never throws: status updates are
   * best-effort and must not abort an evaluation. Patches carrying a terminal
   * phase get more attempts with longer backoff; if even those are exhausted
   * the patch is remembered and re-attempted by flushTerminalPatch() from the
   * shutdown path, so a lost terminal write does not strand the run
   * non-terminally. A 404 (run deleted) aborts immediately — there is
   * nothing left to write to.
   */
  async patchStatus(partial: Partial<MCPEvaluationRunStatus>): Promise<void> {
    const body = { status: partial };
    const isTerminal = partial.phase === "Completed" || partial.phase === "Failed";
    const delays = isTerminal ? TERMINAL_RETRY_DELAYS : RETRY_DELAYS;
    for (let attempt = 0; attempt <= delays.length; attempt++) {
      try {
        await this.api.patchNamespacedCustomObjectStatus(
          {
            group: API_GROUP,
            version: API_VERSION,
            namespace: this.namespace,
            plural: PLURAL_RUNS,
            name: this.runName,
            body,
          },
          k8s.setHeaderOptions("Content-Type", k8s.PatchStrategy.MergePatch),
        );
        this.log.debug("status patched", { keys: Object.keys(partial) });
        if (isTerminal) this.pendingTerminalPatch = null;
        return;
      } catch (err) {
        if (httpStatusCode(err) === 404) {
          this.log.error("run object is gone; abandoning status patch", { keys: Object.keys(partial) });
          return;
        }
        const delay = delays[attempt];
        this.log.warn("status patch failed", { attempt: attempt + 1, error: errorMessage(err), keys: Object.keys(partial) });
        if (delay === undefined) {
          if (isTerminal) {
            this.pendingTerminalPatch = partial;
            this.log.error("terminal status patch abandoned after retries; a final flush will be attempted", {
              keys: Object.keys(partial),
            });
          } else {
            this.log.error("status patch abandoned after retries", { keys: Object.keys(partial) });
          }
          return;
        }
        await sleep(delay);
      }
    }
  }

  async flushTerminalPatch(): Promise<void> {
    const partial = this.pendingTerminalPatch;
    if (partial === null) return;
    this.log.warn("flushing previously abandoned terminal patch", { keys: Object.keys(partial) });
    const body = { status: partial };
    for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt++) {
      try {
        await this.api.patchNamespacedCustomObjectStatus(
          {
            group: API_GROUP,
            version: API_VERSION,
            namespace: this.namespace,
            plural: PLURAL_RUNS,
            name: this.runName,
            body,
          },
          k8s.setHeaderOptions("Content-Type", k8s.PatchStrategy.MergePatch),
        );
        this.log.info("abandoned terminal patch recovered", { keys: Object.keys(partial) });
        this.pendingTerminalPatch = null;
        return;
      } catch (err) {
        if (httpStatusCode(err) === 404) {
          this.log.error("run object is gone; terminal patch cannot be flushed");
          return;
        }
        const delay = RETRY_DELAYS[attempt];
        if (delay === undefined) {
          this.log.error("terminal patch still unwritable; verdict survives in the termination message", {
            keys: Object.keys(partial),
          });
          return;
        }
        await sleep(delay);
      }
    }
  }

  /**
   * Best-effort ConfigMap persistence of the full evaluation report (see
   * StatusWriter). Same reliability class as patchStatus: every failure is a
   * warning and never propagates — the /output copy and the termination
   * message remain the fallbacks. On 409 AlreadyExists (the Job was recreated
   * after a bounded retry and the evaluator re-ran) the existing ConfigMap is
   * replaced.
   */
  async persistReport(report: EvaluationReport): Promise<void> {
    const name = `${this.runName}-report`;
    const reportJson = JSON.stringify(report, null, 2);
    try {
      const ownerRef = await this.runOwnerReference();
      const body: k8s.V1ConfigMap = {
        apiVersion: "v1",
        kind: "ConfigMap",
        metadata: {
          name,
          namespace: this.namespace,
          ...(ownerRef === null ? {} : { ownerReferences: [ownerRef] }),
        },
        data: reportConfigMapData(report, reportJson),
      };
      try {
        await this.core.createNamespacedConfigMap({ namespace: this.namespace, body });
        this.log.info("report configmap created", {
          configmap: `${this.namespace}/${name}`,
          keys: Object.keys(body.data ?? {}),
        });
      } catch (err) {
        if (httpStatusCode(err) !== 409) {
          throw err;
        }
        await this.core.replaceNamespacedConfigMap({ name, namespace: this.namespace, body });
        this.log.info("report configmap updated (already existed)", {
          configmap: `${this.namespace}/${name}`,
          keys: Object.keys(body.data ?? {}),
        });
      }
    } catch (err) {
      this.log.warn("report configmap persistence failed; the report remains in the pod's output dir", {
        configmap: `${this.namespace}/${name}`,
        error: errorMessage(err),
      });
    }
  }

  /**
   * GET the MCPEvaluationRun to build an ownerReference from its uid, so the
   * report ConfigMap is garbage-collected with the run. Returns null (with a
   * warning) when the run cannot be fetched — persistence proceeds without
   * the ownerReference rather than losing the report.
   */
  private async runOwnerReference(): Promise<k8s.V1OwnerReference | null> {
    try {
      const raw: unknown = await this.api.getNamespacedCustomObject({
        group: API_GROUP,
        version: API_VERSION,
        namespace: this.namespace,
        plural: PLURAL_RUNS,
        name: this.runName,
      });
      const metadata = isRecord(raw) && isRecord(raw["metadata"]) ? raw["metadata"] : undefined;
      const uid = metadata && typeof metadata["uid"] === "string" ? metadata["uid"] : undefined;
      if (!isNonEmptyString(uid)) {
        this.log.warn("run has no metadata.uid; report configmap will lack an ownerReference", { run: this.runName });
        return null;
      }
      return {
        apiVersion: `${API_GROUP}/${API_VERSION}`,
        kind: "MCPEvaluationRun",
        name: this.runName,
        uid,
        controller: false,
        blockOwnerDeletion: false,
      };
    } catch (err) {
      this.log.warn("cannot fetch run uid; report configmap will lack an ownerReference", {
        run: this.runName,
        error: errorMessage(err),
      });
      return null;
    }
  }
}

export class DryRunStatusWriter implements StatusWriter {
  private readonly outputDir: string;
  private readonly log: Logger;

  constructor(outputDir: string) {
    this.outputDir = outputDir;
    this.log = rootLogger.child("dryrun");
  }

  async fetchAgent(name: string): Promise<OpenCodeAgent> {
    const direct = path.join(this.outputDir, "agents", `${name}.json`);
    let raw: unknown;
    try {
      if (fs.existsSync(direct)) {
        raw = JSON.parse(fs.readFileSync(direct, "utf8")) as unknown;
      } else {
        raw = this.scanAgents(name);
      }
    } catch (err) {
      throw new ConfigurationError(`dry-run: failed to read agent ${name}: ${errorMessage(err)}`);
    }
    if (raw === undefined) {
      throw new ConfigurationError(`dry-run: agent ${name} not found under ${path.join(this.outputDir, "agents")}`);
    }
    return assertOpenCodeAgent(raw);
  }

  async fetchServer(name: string): Promise<MCPServer> {
    const file = path.join(this.outputDir, "server.json");
    let raw: unknown;
    try {
      if (fs.existsSync(file)) {
        raw = JSON.parse(fs.readFileSync(file, "utf8")) as unknown;
      }
    } catch (err) {
      throw new ConfigurationError(`dry-run: failed to read ${file}: ${errorMessage(err)}`);
    }
    if (raw === undefined) {
      raw = {
        apiVersion: `${API_GROUP}/${API_VERSION}`,
        kind: "MCPServer",
        metadata: { name },
        spec: {
          repositoryUrl: "https://example.invalid/dry-run.git",
          ref: "main",
          transport: process.env["TRANSPORT"] ?? "stdio",
          schedule: "0 0 * * *",
          active: true,
          agentSuite: [],
        },
      };
    }
    return assertMCPServer(raw);
  }

  async patchStatus(partial: Partial<MCPEvaluationRunStatus>): Promise<void> {
    this.log.info("dry-run status patch", { patch: partial });
  }

  async flushTerminalPatch(): Promise<void> {
    // Dry-run patches never fail, so there is nothing to flush.
  }

  async persistReport(report: EvaluationReport): Promise<void> {
    // No API server is contacted in dry-run: the size policy is exercised
    // locally and the resulting ConfigMap shape is logged instead.
    const data = reportConfigMapData(report, JSON.stringify(report, null, 2));
    this.log.info("dry-run report configmap (not persisted)", {
      configmap: `${report.runName}-report`,
      keys: Object.keys(data),
    });
  }

  private scanAgents(name: string): unknown {
    const dir = path.join(this.outputDir, "agents");
    if (!fs.existsSync(dir)) {
      return undefined;
    }
    for (const entry of fs.readdirSync(dir)) {
      if (!entry.endsWith(".json")) {
        continue;
      }
      const parsed = JSON.parse(fs.readFileSync(path.join(dir, entry), "utf8")) as unknown;
      if (isRecord(parsed) && isRecord(parsed["metadata"]) && parsed["metadata"]["name"] === name) {
        return parsed;
      }
    }
    return undefined;
  }
}

export function createStatusWriter(dryRun: boolean, namespace: string, runName: string, outputDir: string): StatusWriter {
  if (dryRun) {
    return new DryRunStatusWriter(outputDir);
  }
  return new K8sStatusWriter(namespace, runName);
}
