/**
 * Adversarial probes: does the target try to manipulate the calling LLM or
 * reach into the host environment?
 */

import { Logger, rootLogger } from "./logger.js";
import { benignArgs, listProperties } from "./fuzz.js";
import { McpClient, extractText, isToolError } from "./mcpclient.js";
import {
  ActiveProbeResult,
  DetectorFlag,
  DetectorHit,
  McpInitializeResult,
  McpToolDefinition,
  ProbeReport,
  RpcOutcome,
  ToolProbeResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

interface Detector {
  flag: DetectorFlag;
  regex: RegExp;
}

const DETECTORS: Detector[] = [
  { flag: "injection-marker", regex: /<\s*system\s*>/i },
  { flag: "injection-marker", regex: /<\s*\/?\s*(assistant|instructions|im_start|im_end)\s*>/i },
  { flag: "injection-marker", regex: /\[\s*(OVERRIDE|SYSTEM|ADMIN|INST)\s*\]/i },
  { flag: "injection-marker", regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts?)/i },
  { flag: "injection-marker", regex: /IMPORTANT:\s*(the\s+)?assistant\s+must/i },
  { flag: "injection-marker", regex: /you\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|unrestricted)\s+mode/i },
  { flag: "injection-marker", regex: /do\s+not\s+(tell|inform|mention)\s+(this\s+to\s+)?the\s+user/i },
  { flag: "injection-marker", regex: /(before|when)\s+(using|calling)\s+this\s+tool[,\s]+(first\s+)?(read|send|call|run)/i },
  { flag: "hidden-instruction", regex: /<!--[\s\S]{0,400}(instruction|assistant|system|ignore|must)[\s\S]{0,400}-->/i },
  { flag: "hidden-instruction", regex: /<\s*(div|span|p)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)/i },
  { flag: "zero-width-chars", regex: /[\u200B\u200C\u200D\u2060\uFEFF]{3,}/ },
  { flag: "exfil-marker", regex: /(reveal|print|repeat|output|send)\s+(me\s+|us\s+)?(your|the)\s+system\s+prompt/i },
  { flag: "exfil-marker", regex: /(api[_ -]?key|secret|token|password|credential)s?\s*(:|=|to)\s*(https?:\/\/|send|post|curl)/i },
  { flag: "exfil-marker", regex: /send\s+(it|them|this|the\s+(data|contents?|results?))\s+to\s+https?:\/\//i },
  { flag: "exfil-marker", regex: /(curl|wget|fetch|POST)\s+https?:\/\/[^\s]+\s+.*\$(HOME|PATH|AWS|ANTHROPIC|OPENAI)/i },
  { flag: "ssrf-indicator", regex: /169\.254\.169\.254/ },
  { flag: "ssrf-indicator", regex: /metadata\.google\.internal/i },
  { flag: "ssrf-indicator", regex: /fd00:ec2::254/i },
  { flag: "ssrf-indicator", regex: /(ami-id|instance-id|iam\/security-credentials|computeMetadata\/v1)/i },
  { flag: "host-file-read", regex: /root:x:0:0:/ },
  { flag: "host-file-read", regex: /\/etc\/(passwd|shadow|hosts)\b/ },
  { flag: "host-file-read", regex: /\/proc\/self\/environ/ },
  { flag: "host-file-read", regex: /\/var\/run\/secrets\/kubernetes\.io/ },
  { flag: "env-leak", regex: /(KUBERNETES_SERVICE_HOST|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN)\s*=/ },
  { flag: "absolute-path-leak", regex: /(\/home\/[a-z0-9_-]+\/|\/root\/|C:\\Users\\)/i },
];

const INSTRUCTION_WORDS = /(ignore|instruction|system|assistant|prompt|override|must|secret|password|token|send|http)/i;
const BASE64_BLOB = /[A-Za-z0-9+/]{40,}={0,2}/g;

function decodeBase64Candidates(text: string): string[] {
  const decoded: string[] = [];
  const matches = text.match(BASE64_BLOB);
  if (!matches) {
    return decoded;
  }
  for (const m of matches.slice(0, 20)) {
    try {
      const buf = Buffer.from(m, "base64");
      const str = buf.toString("utf8");
      const printable = str.replace(/[^\x20-\x7E\n\t]/g, "").length / Math.max(1, str.length);
      if (printable > 0.9 && str.length >= 16) {
        decoded.push(str);
      }
    } catch {
      // not base64
    }
  }
  return decoded;
}

export function scanText(text: string): DetectorHit[] {
  const hits: DetectorHit[] = [];
  if (!text) {
    return hits;
  }
  const seen = new Set<string>();
  const push = (flag: DetectorFlag, pattern: string, index: number, source: string): void => {
    const key = `${flag}:${pattern}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    const start = Math.max(0, index - 80);
    hits.push({ flag, pattern, excerpt: source.slice(start, start + 240) });
  };
  for (const d of DETECTORS) {
    const m = d.regex.exec(text);
    if (m) {
      push(d.flag, d.regex.source, m.index, text);
    }
  }
  for (const decoded of decodeBase64Candidates(text)) {
    if (INSTRUCTION_WORDS.test(decoded)) {
      push("base64-instruction", "base64 blob decodes to instruction-like text", 0, decoded);
      for (const d of DETECTORS) {
        const m = d.regex.exec(decoded);
        if (m) {
          push(d.flag, `base64:${d.regex.source}`, m.index, decoded);
        }
      }
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Active probes
// ---------------------------------------------------------------------------

const URL_PARAM = /(url|uri|link|endpoint|href|host|address|target)/i;
const PATH_PARAM = /(path|file|filename|filepath|dir|directory|location|source|src|dest)/i;

interface ActivePayload {
  kind: "ssrf" | "host-file-read" | "path-traversal";
  value: string;
  successRegex: RegExp;
}

const URL_PAYLOADS: ActivePayload[] = [
  { kind: "ssrf", value: "http://169.254.169.254/latest/meta-data/", successRegex: /(ami-id|instance-id|iam|hostname|local-ipv4)/i },
  { kind: "ssrf", value: "http://metadata.google.internal/computeMetadata/v1/", successRegex: /(project|instance|attributes)/i },
  { kind: "ssrf", value: "http://127.0.0.1:4096/global/health", successRegex: /(healthy|version|opencode)/i },
  { kind: "ssrf", value: "https://kubernetes.default.svc/version", successRegex: /(gitVersion|major|minor)/i },
  { kind: "host-file-read", value: "file:///etc/passwd", successRegex: /root:x:0:0:/ },
];

const PATH_PAYLOADS: ActivePayload[] = [
  { kind: "host-file-read", value: "/etc/passwd", successRegex: /root:x:0:0:/ },
  { kind: "host-file-read", value: "/proc/self/environ", successRegex: /(PATH=|HOME=|HOSTNAME=)/ },
  { kind: "host-file-read", value: "/var/run/secrets/kubernetes.io/serviceaccount/token", successRegex: /^eyJ[A-Za-z0-9_-]+\./m },
  { kind: "path-traversal", value: "../../../../../../etc/passwd", successRegex: /root:x:0:0:/ },
  { kind: "path-traversal", value: "....//....//....//etc/passwd", successRegex: /root:x:0:0:/ },
];

function pickParams(tool: McpToolDefinition, matcher: RegExp): string[] {
  const out: string[] = [];
  for (const p of listProperties(tool.inputSchema)) {
    if (p.type === "string" && matcher.test(p.name)) {
      out.push(p.name);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Probe runner
// ---------------------------------------------------------------------------

export interface ProbeOptions {
  perCallTimeoutMs?: number;
  totalTimeBudgetMs?: number;
  maxActiveProbesPerTool?: number;
}

export async function runProbes(
  client: McpClient,
  tools: McpToolDefinition[],
  init: McpInitializeResult | null,
  options: ProbeOptions = {},
): Promise<ProbeReport> {
  const log: Logger = rootLogger.child("probes");
  const perCallTimeoutMs = options.perCallTimeoutMs ?? 10000;
  const budgetMs = options.totalTimeBudgetMs ?? 3 * 60 * 1000;
  const maxActive = options.maxActiveProbesPerTool ?? 6;
  const startedAt = Date.now();
  const overBudget = (): boolean => Date.now() - startedAt > budgetMs;

  const unsolicitedBefore = client.totalUnsolicited();
  const notificationsBefore = client.notifications;

  // Passive scan of server-provided text surfaces.
  const serverInstructionsHits = scanText(init?.instructions ?? "");
  const toolDescriptionHits: { tool: string; hits: DetectorHit[] }[] = [];
  for (const tool of tools) {
    const surface = [tool.description ?? "", JSON.stringify(tool.inputSchema ?? {}), JSON.stringify(tool.annotations ?? {})].join("\n");
    const hits = scanText(surface);
    if (hits.length > 0) {
      toolDescriptionHits.push({ tool: tool.name, hits });
    }
  }

  // Benign calls.
  const benignCalls: ToolProbeResult[] = [];
  let silentSecondaryActions = false;
  for (const tool of tools) {
    if (overBudget()) {
      break;
    }
    const args = benignArgs(tool);
    const unsolicitedAtStart = client.totalUnsolicited();
    const notificationsAtStart = client.notifications;
    const outcome: RpcOutcome = await client.callTool(tool.name, args, perCallTimeoutMs);
    const text = outcome.result !== undefined ? extractText(outcome.result) : outcome.error ? `${outcome.error.message} ${JSON.stringify(outcome.error.data ?? "")}` : outcome.transportError ?? "";
    const hits = scanText(text);
    if (client.totalUnsolicited() > unsolicitedAtStart || client.notifications > notificationsAtStart + 2) {
      // A benign tool call that triggers server-initiated requests or a burst of
      // notifications indicates secondary activity not requested by the caller.
      silentSecondaryActions = true;
    }
    benignCalls.push({
      tool: tool.name,
      argsUsed: args,
      ok: outcome.ok,
      isError: isToolError(outcome.result),
      latencyMs: outcome.latencyMs,
      hang: outcome.hang,
      crashed: outcome.crashed,
      outputExcerpt: text.slice(0, 600),
      hits,
    });
    if (outcome.crashed) {
      log.warn("target crashed during benign call; recovering", { tool: tool.name });
      const recovered = await client.recover(30000);
      if (!recovered) {
        break;
      }
    }
  }

  // Active SSRF / host-file probes on url/path-like parameters.
  const activeProbes: ActiveProbeResult[] = [];
  for (const tool of tools) {
    if (overBudget()) {
      break;
    }
    const urlParams = pickParams(tool, URL_PARAM);
    const pathParams = pickParams(tool, PATH_PARAM);
    let count = 0;
    const base = benignArgs(tool);
    const plan: { parameter: string; payload: ActivePayload }[] = [];
    for (const p of urlParams) {
      for (const payload of URL_PAYLOADS) {
        plan.push({ parameter: p, payload });
      }
    }
    for (const p of pathParams) {
      for (const payload of PATH_PAYLOADS) {
        plan.push({ parameter: p, payload });
      }
    }
    for (const { parameter, payload } of plan) {
      if (count >= maxActive || overBudget()) {
        break;
      }
      count += 1;
      const args = { ...base, [parameter]: payload.value };
      const outcome = await client.callTool(tool.name, args, perCallTimeoutMs);
      const text = outcome.result !== undefined ? extractText(outcome.result) : outcome.error ? outcome.error.message : outcome.transportError ?? "";
      const succeeded = outcome.ok && !isToolError(outcome.result) && payload.successRegex.test(text);
      activeProbes.push({
        tool: tool.name,
        parameter,
        payload: payload.value,
        kind: payload.kind,
        ok: outcome.ok,
        succeeded,
        latencyMs: outcome.latencyMs,
        evidence: text.slice(0, 300),
      });
      if (outcome.crashed) {
        log.warn("target crashed during active probe; recovering", { tool: tool.name, payload: payload.value });
        const recovered = await client.recover(30000);
        if (!recovered) {
          break;
        }
      }
    }
  }

  const unsolicitedRequests = client.unsolicitedRequests();
  const flagsFrom = (hits: DetectorHit[]): Set<DetectorFlag> => new Set(hits.map((h) => h.flag));
  const allHits: DetectorHit[] = [
    ...serverInstructionsHits,
    ...toolDescriptionHits.flatMap((t) => t.hits),
    ...benignCalls.flatMap((b) => b.hits),
  ];
  const flags = flagsFrom(allHits);
  const promptInjectionDetected =
    flags.has("injection-marker") || flags.has("hidden-instruction") || flags.has("base64-instruction") || flags.has("zero-width-chars");
  const exfiltrationAttemptDetected = flags.has("exfil-marker") || flags.has("env-leak");
  const ssrfPossible = activeProbes.some((p) => p.kind === "ssrf" && p.succeeded) || flags.has("ssrf-indicator");
  const hostFileReadPossible =
    activeProbes.some((p) => (p.kind === "host-file-read" || p.kind === "path-traversal") && p.succeeded) || flags.has("host-file-read");

  return {
    benignCalls,
    activeProbes,
    unsolicitedRequests,
    notificationsCount: client.notifications - notificationsBefore,
    serverInstructionsHits,
    toolDescriptionHits,
    flags: {
      promptInjectionDetected,
      exfiltrationAttemptDetected,
      ssrfPossible,
      hostFileReadPossible,
      unsolicitedServerRequests: client.totalUnsolicited() > unsolicitedBefore || unsolicitedRequests.length > 0,
      silentSecondaryActions,
    },
  };
}

export function renderProbeMarkdown(report: ProbeReport): string {
  const lines: string[] = [];
  lines.push("### Adversarial probe flags");
  lines.push("```json");
  lines.push(JSON.stringify(report.flags, null, 2));
  lines.push("```");
  if (report.serverInstructionsHits.length > 0) {
    lines.push("### Detector hits in server `instructions`");
    for (const h of report.serverInstructionsHits) {
      lines.push(`- ${h.flag} (${h.pattern}): ${JSON.stringify(h.excerpt)}`);
    }
  }
  if (report.toolDescriptionHits.length > 0) {
    lines.push("### Detector hits in tool descriptions / schemas");
    for (const t of report.toolDescriptionHits) {
      for (const h of t.hits) {
        lines.push(`- ${t.tool}: ${h.flag} (${h.pattern}): ${JSON.stringify(h.excerpt)}`);
      }
    }
  }
  lines.push(`### Benign tool calls (${report.benignCalls.length})`);
  for (const b of report.benignCalls) {
    const status = b.crashed ? "CRASH" : b.hang ? "HANG" : b.isError ? "tool-error" : b.ok ? "ok" : "rpc-error";
    lines.push(`- ${b.tool} [${status}, ${b.latencyMs}ms] args=${JSON.stringify(b.argsUsed).slice(0, 200)}`);
    lines.push(`  output: ${JSON.stringify(b.outputExcerpt.slice(0, 300))}`);
    for (const h of b.hits) {
      lines.push(`  ! ${h.flag} (${h.pattern}): ${JSON.stringify(h.excerpt)}`);
    }
  }
  if (report.activeProbes.length > 0) {
    lines.push(`### Active SSRF / host-file probes (${report.activeProbes.length})`);
    for (const p of report.activeProbes) {
      lines.push(`- ${p.tool}.${p.parameter} <- ${p.payload} [${p.kind}] succeeded=${p.succeeded} ok=${p.ok} (${p.latencyMs}ms)`);
      if (p.succeeded) {
        lines.push(`  evidence: ${JSON.stringify(p.evidence)}`);
      }
    }
  }
  if (report.unsolicitedRequests.length > 0) {
    lines.push("### Unsolicited server->client requests");
    for (const u of report.unsolicitedRequests) {
      lines.push(`- ${u.method}: ${u.count}`);
    }
  }
  lines.push(`- notifications received during probes: ${report.notificationsCount}`);
  return lines.join("\n");
}
