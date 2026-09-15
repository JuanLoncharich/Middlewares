/**
 * Kubernetes access for the runner: fetches OpenCodeAgent / MCPServer CRs and
 * patches MCPEvaluationRun status via the status subresource.
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
  MCPEvaluationRunStatus,
  MCPServer,
  OpenCodeAgent,
  PLURAL_AGENTS,
  PLURAL_RUNS,
  PLURAL_SERVERS,
  assertMCPServer,
  assertOpenCodeAgent,
  errorMessage,
  isRecord,
} from "./types.js";

export interface StatusWriter {
  fetchAgent(name: string): Promise<OpenCodeAgent>;
  fetchServer(name: string): Promise<MCPServer>;
  patchStatus(partial: Partial<MCPEvaluationRunStatus>): Promise<void>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class K8sStatusWriter implements StatusWriter {
  private readonly namespace: string;
  private readonly runName: string;
  private readonly api: k8s.CustomObjectsApi;
  private readonly log: Logger;

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
  }

  async fetchAgent(name: string): Promise<OpenCodeAgent> {
    let raw: unknown;
    try {
      raw = await this.api.getNamespacedCustomObject({
        group: API_GROUP,
        version: API_VERSION,
        namespace: this.namespace,
        plural: PLURAL_AGENTS,
        name,
      });
    } catch (err) {
      throw new ConfigurationError(`failed to fetch OpenCodeAgent ${this.namespace}/${name}: ${errorMessage(err)}`);
    }
    return assertOpenCodeAgent(raw);
  }

  async fetchServer(name: string): Promise<MCPServer> {
    let raw: unknown;
    try {
      raw = await this.api.getNamespacedCustomObject({
        group: API_GROUP,
        version: API_VERSION,
        namespace: this.namespace,
        plural: PLURAL_SERVERS,
        name,
      });
    } catch (err) {
      throw new ConfigurationError(`failed to fetch MCPServer ${this.namespace}/${name}: ${errorMessage(err)}`);
    }
    return assertMCPServer(raw);
  }

  /**
   * Merge-patches the status subresource. Never throws: status updates are
   * best-effort and must not abort an evaluation. Retries 3 times with backoff.
   */
  async patchStatus(partial: Partial<MCPEvaluationRunStatus>): Promise<void> {
    const body = { status: partial };
    const delays = [500, 1500, 4000];
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
        return;
      } catch (err) {
        const delay = delays[attempt];
        this.log.warn("status patch failed", { attempt: attempt + 1, error: errorMessage(err), keys: Object.keys(partial) });
        if (delay === undefined) {
          this.log.error("status patch abandoned after retries", { keys: Object.keys(partial) });
          return;
        }
        await sleep(delay);
      }
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
