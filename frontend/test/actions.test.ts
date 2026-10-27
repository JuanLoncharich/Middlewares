import { type AddressInfo } from "node:net";
import { type Server, createServer } from "node:http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type ServerStore, handleAction, mergePatchBody } from "../server/actions.ts";
import type { MCPServer } from "../src/model/crd.ts";
import { LABEL_FLUX, LABEL_MANAGED_BY, MANAGED_BY_UI, MAX_UI_SERVERS } from "../src/model/serverForm.ts";

function server(name: string, labels: Record<string, string> = {}, active = true): MCPServer {
  return {
    apiVersion: "security.eval.io/v1alpha1",
    kind: "MCPServer",
    metadata: { name, labels },
    spec: { repositoryUrl: "https://github.com/x/y", schedule: "0 3 * * *", active, agentSuite: [] },
  };
}

let servers: MCPServer[] = [];
const calls: { op: string; name: string; body?: unknown }[] = [];
const store: ServerStore = {
  namespace: "mcp-evals",
  servers: () => servers,
  agentNames: () => ["mcp-sast-auditor", "mcp-fuzz-tester", "mcp-rogue-detector", "mcp-synthesizer"],
  create: async (s) => void calls.push({ op: "create", name: s.metadata.name, body: s }),
  patch: async (name, body) => void calls.push({ op: "patch", name, body }),
  remove: async (name) => void calls.push({ op: "delete", name }),
};

let ui: Server;
let base = "";
beforeAll(async () => {
  ui = createServer((req, res) => void handleAction(req, res, store));
  base = await new Promise((r) => ui.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(ui.address() as AddressInfo).port}`)));
});
afterAll(() => ui.close());
beforeEach(() => {
  calls.length = 0;
  servers = [
    server("filesystem-mcp", { [LABEL_FLUX]: "platform" }),
    server("mine", { [LABEL_MANAGED_BY]: MANAGED_BY_UI }),
    server("paused", { [LABEL_MANAGED_BY]: MANAGED_BY_UI }, false),
  ];
});

function req(method: string, path: string, body?: unknown, origin: string | null = base) {
  return fetch(`${base}${path}`, {
    method,
    headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...(origin ? { origin } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const form = { name: "weather-mcp", repositoryUrl: "https://github.com/acme/weather-mcp.git", ref: "main", path: "", transport: "stdio", targetPort: "8080", schedule: "daily" };

describe("server actions", () => {
  it("creates a labelled MCPServer that is evaluated right away", async () => {
    const res = await req("POST", "/api/servers", form);
    expect(res.status).toBe(201);
    const created = calls[0]!.body as MCPServer;
    expect(created.metadata.labels?.[LABEL_MANAGED_BY]).toBe(MANAGED_BY_UI);
    expect(created.metadata.annotations?.["security.eval.io/trigger-now"]).toBe("true");
    expect(created.metadata.namespace).toBe("mcp-evals");
    expect(created.spec.schedule).toBe("0 3 * * *");
    expect(created.spec.agentSuite.map((a) => a.name)).toEqual(["mcp-sast-auditor", "mcp-fuzz-tester", "mcp-rogue-detector", "mcp-synthesizer"]);
  });

  it("rejects bad fields with per-field errors and never calls the cluster", async () => {
    const res = await req("POST", "/api/servers", { ...form, name: "Mine!", repositoryUrl: "http://evil", path: "../etc" });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { fields: Record<string, string> };
    expect(Object.keys(body.fields).sort()).toEqual(["name", "path", "repositoryUrl"]);
    expect((await req("POST", "/api/servers", { ...form, name: "mine" })).status).toBe(400);
    expect(calls).toHaveLength(0);
  });

  it("caps how many servers the UI can create", async () => {
    servers = Array.from({ length: MAX_UI_SERVERS }, (_, i) => server(`s${i}`, { [LABEL_MANAGED_BY]: MANAGED_BY_UI }));
    expect((await req("POST", "/api/servers", form)).status).toBe(429);
  });

  it("evaluates, pauses, resumes and deletes servers the UI owns", async () => {
    expect((await req("POST", "/api/servers/mine/evaluate")).status).toBe(202);
    expect((await req("POST", "/api/servers/mine/pause", { paused: true })).status).toBe(200);
    expect((await req("POST", "/api/servers/paused/pause", { paused: false })).status).toBe(200);
    expect((await req("DELETE", "/api/servers/mine")).status).toBe(200);
    expect(calls).toEqual([
      { op: "patch", name: "mine", body: { metadata: { annotations: { "security.eval.io/trigger-now": "true" } } } },
      { op: "patch", name: "mine", body: { spec: { active: false } } },
      { op: "patch", name: "paused", body: { spec: { active: true } } },
      { op: "delete", name: "mine" },
    ]);
  });

  it("can evaluate a git-managed server but not pause or delete it", async () => {
    expect((await req("POST", "/api/servers/filesystem-mcp/evaluate")).status).toBe(202);
    expect((await req("POST", "/api/servers/filesystem-mcp/pause", { paused: true })).status).toBe(409);
    expect((await req("DELETE", "/api/servers/filesystem-mcp")).status).toBe(409);
    expect((await req("POST", "/api/servers/paused/evaluate")).status).toBe(409);
    expect(calls.map((c) => c.op)).toEqual(["patch"]);
  });

  it("requires a same-origin request", async () => {
    expect((await req("DELETE", "/api/servers/mine", undefined, null)).status).toBe(403);
    expect((await req("DELETE", "/api/servers/mine", undefined, "https://evil.example")).status).toBe(403);
    expect((await req("POST", "/api/servers/nope/evaluate")).status).toBe(404);
    expect(calls).toHaveLength(0);
  });

  it("keeps the server's name when a patch carries metadata", () => {
    const body = mergePatchBody("security.eval.io/v1alpha1", "MCPServer", "mcp-evals", "mine", {
      metadata: { annotations: { "security.eval.io/trigger-now": "true" } },
    });
    expect(body.metadata).toEqual({ annotations: { "security.eval.io/trigger-now": "true" }, name: "mine", namespace: "mcp-evals" });
    expect(mergePatchBody("v", "K", "ns", "x", { spec: { active: false } })).toEqual({
      apiVersion: "v",
      kind: "K",
      spec: { active: false },
      metadata: { name: "x", namespace: "ns" },
    });
  });
});
