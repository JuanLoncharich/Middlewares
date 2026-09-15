/**
 * Static evidence collection for the SAST agent.
 *
 * Reads the cloned repository from the shared /workspace volume. File
 * discovery and reads go through the OpenCode server (client.find.files /
 * client.file.read) when a client is provided, with node:fs as fallback.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { OpencodeClient } from "@opencode-ai/sdk/v2";
import { Logger, rootLogger } from "./logger.js";
import {
  DependencyEntry,
  ManifestFile,
  RegistrationHit,
  SinkHit,
  StaticEvidence,
  errorMessage,
  isRecord,
} from "./types.js";

const MAX_FILES = 200;
const MAX_FILE_EXCERPT = 40 * 1024;
const MAX_TOTAL_BYTES = 400 * 1024;

const MANIFEST_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "pyproject.toml",
  "requirements.txt",
  "requirements-dev.txt",
  "uv.lock",
  "poetry.lock",
  "go.mod",
  "go.sum",
  "Cargo.toml",
  "Cargo.lock",
]);

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".sh", ".json", ".yaml", ".yml", ".toml"]);

const SKIP_DIRS = new Set(["node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache", "target", "vendor", ".bin", ".cache"]);

interface SinkPattern {
  category: string;
  regex: RegExp;
}

const SINK_PATTERNS: SinkPattern[] = [
  { category: "command-execution", regex: /\bchild_process\b/ },
  { category: "command-execution", regex: /\b(exec|execSync|execFile|execFileSync)\s*\(/ },
  { category: "command-execution", regex: /\b(spawn|spawnSync)\s*\(/ },
  { category: "command-execution", regex: /\bsubprocess\.(run|Popen|call|check_output|check_call)\b/ },
  { category: "command-execution", regex: /\bos\.(system|popen|execv|execl|execvp|spawn)\b/ },
  { category: "command-execution", regex: /\bexec\.Command\s*\(/ },
  { category: "dynamic-code", regex: /\beval\s*\(/ },
  { category: "dynamic-code", regex: /\bnew\s+Function\s*\(/ },
  { category: "dynamic-code", regex: /\b(vm\.runInNewContext|vm\.runInThisContext|vm\.Script)\b/ },
  { category: "dynamic-code", regex: /\bexec\s*\(\s*compile\s*\(/ },
  { category: "raw-socket", regex: /\bnet\.(connect|createConnection|Socket)\b/ },
  { category: "raw-socket", regex: /\bsocket\.(socket|create_connection)\b/ },
  { category: "raw-socket", regex: /\bnet\.Dial\s*\(/ },
  { category: "network-egress", regex: /\b(fetch|axios|got|request|http\.get|https\.get|https\.request|urllib\.request|requests\.(get|post)|httpx\.)\s*\(/ },
  { category: "file-access-absolute", regex: /\b(readFile|readFileSync|writeFile|writeFileSync|open|createReadStream)\s*\(\s*["'`]\/(etc|proc|root|home|var|usr|sys)\b/ },
  { category: "file-access-absolute", regex: /\bopen\s*\(\s*["']\/(etc|proc|root|home|var|sys)\b/ },
  { category: "file-access-traversal", regex: /\.\.\/\.\.\// },
  { category: "hardcoded-secret", regex: /AKIA[0-9A-Z]{16}/ },
  { category: "hardcoded-secret", regex: /\bsk-[A-Za-z0-9_-]{20,}/ },
  { category: "hardcoded-secret", regex: /\bghp_[A-Za-z0-9]{36}\b/ },
  { category: "hardcoded-secret", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/ },
  { category: "hardcoded-secret", regex: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/ },
  { category: "hardcoded-secret", regex: /(api[_-]?key|secret|password|token)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/i },
  { category: "env-access", regex: /\bprocess\.env\.[A-Z_]+/ },
  { category: "env-access", regex: /\bos\.environ(\.get)?\b/ },
  { category: "cloud-metadata", regex: /169\.254\.169\.254|metadata\.google\.internal/ },
  { category: "obfuscation", regex: /\b(atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{40,}["']/ },
  { category: "obfuscation", regex: /\bbase64\.b64decode\s*\(\s*["'][A-Za-z0-9+/=]{40,}["']/ },
  { category: "install-hook", regex: /"(preinstall|postinstall|prepare)"\s*:/ },
];

const REGISTRATION_PATTERNS: RegExp[] = [
  /tools\/list/,
  /registerTool\s*\(/,
  /server\.tool\s*\(/,
  /\.addTool\s*\(/,
  /@mcp\.tool/,
  /@server\.(list_tools|call_tool|list_resources|list_prompts)/,
  /ListToolsRequestSchema/,
  /CallToolRequestSchema/,
  /ListResourcesRequestSchema/,
  /ListPromptsRequestSchema/,
  /\binputSchema\b/,
  /resources\/list/,
  /prompts\/list/,
  /setRequestHandler\s*\(/,
  /FastMCP\s*\(/,
  /mcp\.NewServer|server\.AddTool|mcp\.NewTool/,
];

interface CollectedFile {
  relPath: string;
  content: string;
  truncated: boolean;
}

export interface StaticCollectorOptions {
  workspaceDir: string;
  client?: OpencodeClient;
}

async function listFiles(options: StaticCollectorOptions, log: Logger): Promise<string[]> {
  const viaClient = options.client;
  if (viaClient) {
    try {
      const res = await viaClient.find.files({ query: "", directory: options.workspaceDir, limit: 5000 });
      if (res.data && res.data.length > 0) {
        return res.data
          .map((p) => (path.isAbsolute(p) ? path.relative(options.workspaceDir, p) : p))
          .filter((p) => p.length > 0 && !p.startsWith(".."));
      }
      if (res.error) {
        log.warn("client.find.files returned an error; falling back to fs", { error: JSON.stringify(res.error) });
      }
    } catch (err) {
      log.warn("client.find.files failed; falling back to fs", { error: errorMessage(err) });
    }
  }
  return walkFs(options.workspaceDir);
}

function walkFs(root: string): string[] {
  const out: string[] = [];
  const stack: string[] = [""];
  while (stack.length > 0 && out.length < 20000) {
    const rel = stack.pop() ?? "";
    const abs = path.join(root, rel);
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const childRel = rel ? path.join(rel, entry.name) : entry.name;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          stack.push(childRel);
        }
      } else if (entry.isFile()) {
        out.push(childRel);
      }
    }
  }
  return out.sort();
}

async function readFile(options: StaticCollectorOptions, relPath: string, log: Logger): Promise<string | null> {
  const viaClient = options.client;
  if (viaClient) {
    try {
      const res = await viaClient.file.read({ path: relPath, directory: options.workspaceDir });
      if (res.data && res.data.type === "text") {
        return res.data.content;
      }
      if (res.data && res.data.type === "binary") {
        return null;
      }
    } catch (err) {
      log.debug("client.file.read failed; falling back to fs", { path: relPath, error: errorMessage(err) });
    }
  }
  try {
    const abs = path.join(options.workspaceDir, relPath);
    const stat = fs.statSync(abs);
    if (stat.size > 2 * 1024 * 1024) {
      return null;
    }
    const buf = fs.readFileSync(abs);
    if (buf.includes(0)) {
      return null;
    }
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

function isSkipped(relPath: string): boolean {
  return relPath.split(path.sep).some((seg) => SKIP_DIRS.has(seg));
}

function priority(relPath: string): number {
  const base = path.basename(relPath);
  if (MANIFEST_NAMES.has(base)) {
    return 0;
  }
  if (/^(src|server|lib|app)\b/.test(relPath)) {
    return 1;
  }
  if (/(index|main|server)\.(ts|js|py|go)$/.test(base)) {
    return 1;
  }
  return 2;
}

function parseDependencies(manifests: ManifestFile[]): DependencyEntry[] {
  const deps: DependencyEntry[] = [];
  for (const m of manifests) {
    const base = path.basename(m.path);
    try {
      if (base === "package.json") {
        const parsed = JSON.parse(m.content) as unknown;
        if (isRecord(parsed)) {
          for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
            const block = parsed[section];
            if (isRecord(block)) {
              for (const [name, version] of Object.entries(block)) {
                deps.push({ ecosystem: "npm", name, version: typeof version === "string" ? version : "?", source: `${m.path}#${section}` });
              }
            }
          }
        }
      } else if (base === "requirements.txt" || base === "requirements-dev.txt") {
        for (const line of m.content.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) {
            continue;
          }
          const match = /^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]+.*)?$/.exec(trimmed);
          if (match) {
            deps.push({ ecosystem: "pypi", name: match[1] ?? trimmed, version: (match[2] ?? "*").trim(), source: m.path });
          }
        }
      } else if (base === "pyproject.toml") {
        const section = /\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/.exec(m.content);
        if (section && section[1]) {
          for (const raw of section[1].split(",")) {
            const item = raw.trim().replace(/^["']|["']$/g, "");
            if (item) {
              const match = /^([A-Za-z0-9_.\-\[\]]+)\s*(.*)$/.exec(item);
              deps.push({ ecosystem: "pypi", name: match?.[1] ?? item, version: (match?.[2] ?? "*").trim() || "*", source: m.path });
            }
          }
        }
        const poetry = /\[tool\.poetry\.dependencies\]([\s\S]*?)(\n\[|$)/.exec(m.content);
        if (poetry && poetry[1]) {
          for (const line of poetry[1].split("\n")) {
            const match = /^\s*([A-Za-z0-9_.\-]+)\s*=\s*(.+)$/.exec(line);
            if (match && match[1] && match[1] !== "python") {
              deps.push({ ecosystem: "pypi", name: match[1], version: (match[2] ?? "*").trim(), source: m.path });
            }
          }
        }
      } else if (base === "go.mod") {
        for (const line of m.content.split("\n")) {
          const match = /^\s*([a-zA-Z0-9.\-_/]+\.[a-z]+\/[^\s]+)\s+(v[^\s]+)/.exec(line);
          if (match && match[1] && match[2]) {
            deps.push({ ecosystem: "go", name: match[1], version: match[2], source: m.path });
          }
        }
      } else if (base === "Cargo.toml") {
        const section = /\[dependencies\]([\s\S]*?)(\n\[|$)/.exec(m.content);
        if (section && section[1]) {
          for (const line of section[1].split("\n")) {
            const match = /^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+)$/.exec(line);
            if (match && match[1]) {
              deps.push({ ecosystem: "cargo", name: match[1], version: (match[2] ?? "*").trim(), source: m.path });
            }
          }
        }
      }
    } catch (err) {
      deps.push({ ecosystem: "npm", name: `<parse-error:${m.path}>`, version: errorMessage(err), source: m.path });
    }
  }
  return deps;
}

function scanFile(relPath: string, content: string, sinks: SinkHit[], registrations: RegistrationHit[]): void {
  const lines = content.split("\n");
  const isManifest = MANIFEST_NAMES.has(path.basename(relPath));
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (line.length > 2000) {
      continue;
    }
    for (const sp of SINK_PATTERNS) {
      if (sp.category === "install-hook" && !isManifest) {
        continue;
      }
      if (sp.regex.test(line)) {
        sinks.push({ file: relPath, line: i + 1, pattern: sp.regex.source, category: sp.category, snippet: line.trim().slice(0, 200) });
      }
    }
    for (const rp of REGISTRATION_PATTERNS) {
      if (rp.test(line)) {
        registrations.push({ file: relPath, line: i + 1, pattern: rp.source, snippet: line.trim().slice(0, 200) });
        break;
      }
    }
  }
}

export async function collectStaticEvidence(options: StaticCollectorOptions): Promise<StaticEvidence> {
  const log = rootLogger.child("static");
  const allFiles = (await listFiles(options, log)).filter((f) => !isSkipped(f));
  const candidates = allFiles
    .filter((f) => MANIFEST_NAMES.has(path.basename(f)) || SOURCE_EXTENSIONS.has(path.extname(f)))
    .sort((a, b) => priority(a) - priority(b) || a.localeCompare(b))
    .slice(0, MAX_FILES);

  const manifests: ManifestFile[] = [];
  const sinks: SinkHit[] = [];
  const registrations: RegistrationHit[] = [];
  const filesSampled: string[] = [];
  const collected: CollectedFile[] = [];
  let totalBytes = 0;
  let truncated = allFiles.length > candidates.length;

  for (const rel of candidates) {
    if (totalBytes >= MAX_TOTAL_BYTES) {
      truncated = true;
      break;
    }
    const content = await readFile(options, rel, log);
    if (content === null) {
      continue;
    }
    const excerpt = content.length > MAX_FILE_EXCERPT ? content.slice(0, MAX_FILE_EXCERPT) : content;
    totalBytes += excerpt.length;
    filesSampled.push(rel);
    collected.push({ relPath: rel, content: excerpt, truncated: excerpt.length < content.length });
    if (MANIFEST_NAMES.has(path.basename(rel))) {
      manifests.push({ path: rel, content: excerpt, truncated: excerpt.length < content.length });
    }
    scanFile(rel, excerpt, sinks, registrations);
  }

  let launchFile: unknown = null;
  let runtime = "unknown";
  try {
    const launchPath = path.join(options.workspaceDir, ".mcp-launch.json");
    if (fs.existsSync(launchPath)) {
      launchFile = JSON.parse(fs.readFileSync(launchPath, "utf8")) as unknown;
      if (isRecord(launchFile) && typeof launchFile["runtime"] === "string") {
        runtime = launchFile["runtime"];
      }
    }
  } catch (err) {
    log.warn("could not read launch file", { error: errorMessage(err) });
  }
  if (runtime === "unknown") {
    if (manifests.some((m) => path.basename(m.path) === "package.json")) {
      runtime = "node";
    } else if (manifests.some((m) => /pyproject\.toml|requirements/.test(m.path))) {
      runtime = "python";
    } else if (manifests.some((m) => path.basename(m.path) === "go.mod")) {
      runtime = "go";
    }
  }

  log.info("static evidence collected", {
    files: allFiles.length,
    sampled: filesSampled.length,
    manifests: manifests.length,
    sinks: sinks.length,
    registrations: registrations.length,
    bytes: totalBytes,
  });

  return {
    runtime,
    fileCount: allFiles.length,
    filesSampled,
    manifests,
    dependencies: parseDependencies(manifests),
    registrations: registrations.slice(0, 300),
    sinks: sinks.slice(0, 500),
    launchFile,
    truncated,
    totalBytes,
  };
}

export function renderStaticMarkdown(evidence: StaticEvidence, workspaceDir: string): string {
  const lines: string[] = [];
  lines.push(`### Repository overview`);
  lines.push(`- workspace: ${workspaceDir} (read-only; use your file tools to inspect any file)`);
  lines.push(`- detected runtime: ${evidence.runtime}`);
  lines.push(`- files discovered: ${evidence.fileCount}; sampled: ${evidence.filesSampled.length}; truncated: ${evidence.truncated}`);
  if (evidence.launchFile !== null) {
    lines.push(`- launch descriptor (.mcp-launch.json): ${JSON.stringify(evidence.launchFile)}`);
  }
  lines.push(`### Files sampled`);
  for (const f of evidence.filesSampled.slice(0, 200)) {
    lines.push(`- ${f}`);
  }
  lines.push(`### Dependencies (${evidence.dependencies.length})`);
  for (const d of evidence.dependencies.slice(0, 300)) {
    lines.push(`- [${d.ecosystem}] ${d.name} ${d.version} (${d.source})`);
  }
  lines.push(`### Manifests`);
  for (const m of evidence.manifests) {
    lines.push(`#### ${m.path}${m.truncated ? " (truncated)" : ""}`);
    lines.push("```");
    lines.push(m.content.slice(0, 8000));
    lines.push("```");
  }
  lines.push(`### MCP registration sites (${evidence.registrations.length})`);
  for (const r of evidence.registrations.slice(0, 120)) {
    lines.push(`- ${r.file}:${r.line} :: ${r.snippet}`);
  }
  lines.push(`### Dangerous sink candidates (${evidence.sinks.length})`);
  const byCategory = new Map<string, SinkHit[]>();
  for (const s of evidence.sinks) {
    const list = byCategory.get(s.category) ?? [];
    list.push(s);
    byCategory.set(s.category, list);
  }
  for (const [category, list] of byCategory.entries()) {
    lines.push(`#### ${category} (${list.length})`);
    for (const s of list.slice(0, 60)) {
      lines.push(`- ${s.file}:${s.line} :: ${s.snippet}`);
    }
  }
  return lines.join("\n");
}
