// A tiny stand-in for the Kubernetes API so `npm run live` can be tried
// without a cluster: it replays a demo scenario as real watch events, pods,
// evaluator logs and the report ConfigMap. Only the endpoints server/live.ts
// uses are implemented. Not for anything but local testing.
//
//   npx tsx test/fake-apiserver.ts [scenario]   → writes test/.fake-kubeconfig
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type { ServerResponse } from "node:http";
import { createServer } from "node:https";
import { fileURLToPath } from "node:url";
import { DemoSource } from "../src/data/demo/replay.ts";
import { API_VERSION, LABEL_RUN, isTerminal } from "../src/model/crd.ts";

const PORT = Number(process.env["FAKE_API_PORT"] ?? 16443);
const NS = "mcp-evals";
const scenario = process.argv[2] ?? "vigil";

const demo = new DemoSource(scenario);
demo.start();

let rv = 1;
type Kind = "mcpservers" | "mcpevaluationruns" | "opencodeagents";
const watchers: Record<Kind, Set<ServerResponse>> = { mcpservers: new Set(), mcpevaluationruns: new Set(), opencodeagents: new Set() };
const versions = new Map<string, number>();
const seen = new Map<string, unknown>();

function objects(kind: Kind): Record<string, { metadata: Record<string, unknown> }> {
  const s = demo.getSnapshot();
  return (kind === "mcpservers" ? s.servers : kind === "mcpevaluationruns" ? s.runs : s.agents) as never;
}

function withVersion(kind: Kind, name: string, obj: { metadata: Record<string, unknown> }) {
  const key = `${kind}/${name}`;
  if (seen.get(key) !== obj) {
    seen.set(key, obj);
    versions.set(key, ++rv);
  }
  return { ...obj, metadata: { ...obj.metadata, resourceVersion: String(versions.get(key)), uid: key } };
}

demo.subscribe(() => {
  for (const kind of Object.keys(watchers) as Kind[]) {
    for (const [name, obj] of Object.entries(objects(kind))) {
      const key = `${kind}/${name}`;
      if (seen.get(key) === obj) continue;
      const type = seen.has(key) ? "MODIFIED" : "ADDED";
      const event = JSON.stringify({ type, object: withVersion(kind, name, obj) }) + "\n";
      for (const res of watchers[kind]) res.write(event);
    }
  }
});

function json(res: ServerResponse, code: number, body: unknown): void {
  res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(body));
}

function pod(run: string) {
  const s = demo.getSnapshot();
  const started = (s.logs[run]?.length ?? 0) > 0;
  const r = s.runs[run];
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: { name: `${run}-pod`, namespace: NS, labels: { [LABEL_RUN]: run }, creationTimestamp: r?.metadata.creationTimestamp },
    status: {
      containerStatuses: [
        { name: "evaluator", state: started ? (isTerminal(r?.status?.phase) ? { terminated: { exitCode: 0 } } : { running: {} }) : { waiting: { reason: "PodInitializing" } } },
      ],
    },
  };
}

// client-node only speaks https, so the fake serves a throwaway self-signed cert.
const tlsDir = fileURLToPath(new URL("./.fake-tls/", import.meta.url));
if (!existsSync(`${tlsDir}key.pem`)) {
  mkdirSync(tlsDir, { recursive: true });
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", `${tlsDir}key.pem`, "-out", `${tlsDir}cert.pem`], { stdio: "ignore" });
}

const server = createServer({ key: readFileSync(`${tlsDir}key.pem`), cert: readFileSync(`${tlsDir}cert.pem`) }, (req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  const p = url.pathname;
  const cr = p.match(new RegExp(`^/apis/security\\.eval\\.io/v1alpha1/namespaces/${NS}/(mcpservers|mcpevaluationruns|opencodeagents)$`));
  if (cr) {
    const kind = cr[1] as Kind;
    if (url.searchParams.get("watch") === "true") {
      res.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
      watchers[kind].add(res);
      req.on("close", () => watchers[kind].delete(res));
      return;
    }
    const items = Object.entries(objects(kind)).map(([n, o]) => withVersion(kind, n, o));
    json(res, 200, { apiVersion: API_VERSION, kind: "List", metadata: { resourceVersion: String(rv) }, items });
    return;
  }
  const cm = p.match(new RegExp(`^/api/v1/namespaces/${NS}/configmaps/(.+)-report$`));
  if (cm) {
    const report = demo.getSnapshot().reports[cm[1]!];
    if (!report) return json(res, 404, { kind: "Status", code: 404, reason: "NotFound" });
    return json(res, 200, { apiVersion: "v1", kind: "ConfigMap", metadata: { name: `${cm[1]}-report` }, data: { "report.json": JSON.stringify(report) } });
  }
  if (p === `/api/v1/namespaces/${NS}/pods`) {
    const run = (url.searchParams.get("labelSelector") ?? "").split("=")[1] ?? "";
    const items = demo.getSnapshot().runs[run] ? [pod(run)] : [];
    return json(res, 200, { apiVersion: "v1", kind: "PodList", metadata: {}, items });
  }
  const lg = p.match(new RegExp(`^/api/v1/namespaces/${NS}/pods/(.+)-pod/log$`));
  if (lg) {
    const run = lg[1]!;
    res.writeHead(200, { "content-type": "text/plain", "transfer-encoding": "chunked" });
    let sent = 0;
    const pump = () => {
      const s = demo.getSnapshot();
      const lines = s.logs[run] ?? [];
      // A non-JSON line, like npm noise, which the backend must drop.
      if (sent === 0 && lines.length > 0) res.write("> node dist/evaluator.js\n");
      for (const l of lines.slice(sent)) res.write(JSON.stringify(l) + "\n");
      sent = lines.length;
      if (lines[lines.length - 1]?.msg === "evaluator finished") {
        clearInterval(timer);
        res.end();
      }
    };
    const timer = setInterval(pump, 250);
    pump();
    req.on("close", () => clearInterval(timer));
    return;
  }
  json(res, 404, { kind: "Status", code: 404, message: `fake apiserver: ${p} not implemented` });
});

server.listen(PORT, "127.0.0.1", () => {
  const kubeconfig = fileURLToPath(new URL("./.fake-kubeconfig", import.meta.url));
  writeFileSync(
    kubeconfig,
    `apiVersion: v1
kind: Config
clusters: [{name: fake, cluster: {server: "https://127.0.0.1:${PORT}", insecure-skip-tls-verify: true}}]
users: [{name: fake, user: {token: fake}}]
contexts: [{name: fake, context: {cluster: fake, user: fake, namespace: ${NS}}}]
current-context: fake
`,
  );
  process.stderr.write(`fake apiserver on :${PORT}, scenario ${scenario}; KUBECONFIG=${kubeconfig}\n`);
});
