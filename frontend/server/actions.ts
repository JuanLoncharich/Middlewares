// The UI's write routes, all on MCPServer objects in NAMESPACE and nothing
// else (the Role in frontend/deploy/mcp-eval-ui.yaml grants exactly
// create/patch/delete on mcpservers):
//
//   POST   /api/servers                  create one from the form, evaluated right away
//   POST   /api/servers/<name>/evaluate  evaluate now (trigger-now annotation)
//   POST   /api/servers/<name>/pause     {"paused": true|false}  (spec.active)
//   DELETE /api/servers/<name>           delete it; its runs go with it
//
// Servers that come from git (Flux) can be evaluated but not paused or
// deleted: Flux would put them back on its next reconcile.
//
// Every route requires a same-origin request (Origin header present and equal
// to Host): the browser sends Traefik's basic-auth credentials to any site
// that targets this host, so without the check another page could act here.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { MCPServer } from "../src/model/crd.ts";
import {
  DEFAULT_SUITE,
  EMPTY_FORM,
  LABEL_MANAGED_BY,
  MANAGED_BY_UI,
  MAX_UI_SERVERS,
  type ServerForm,
  isGitManaged,
  serverFromForm,
  validateServerForm,
} from "../src/model/serverForm.ts";
import { isSameOrigin } from "./origin.ts";

/** What the routes need from the cluster; live.ts backs it with the API server, tests with a fake. */
export interface ServerStore {
  namespace: string;
  servers(): MCPServer[];
  agentNames(): string[];
  create(server: MCPServer): Promise<void>;
  /** JSON merge patch on the MCPServer. */
  patch(name: string, patch: Record<string, unknown>): Promise<void>;
  remove(name: string): Promise<void>;
}

const MAX_BODY = 8 * 1024;
const NAME = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("too large");
    chunks.push(chunk as Buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  const value: unknown = text ? JSON.parse(text) : {};
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not an object");
  return value as Record<string, unknown>;
}

function apiError(err: unknown): string {
  const e = err as { code?: number; body?: unknown; message?: string };
  const body = typeof e.body === "string" ? e.body : JSON.stringify(e.body ?? "");
  const msg = /"message":"([^"]+)"/.exec(body)?.[1] ?? e.message ?? String(err);
  return msg.slice(0, 300);
}

export function isActionRoute(url: string | undefined): boolean {
  return !!url && (url === "/api/servers" || url.startsWith("/api/servers/"));
}

export async function handleAction(req: IncomingMessage, res: ServerResponse, store: ServerStore): Promise<void> {
  if (!req.headers.origin || !isSameOrigin(req.headers.origin, req.headers.host)) {
    return send(res, 403, { error: "Origen no permitido." });
  }
  const url = new URL(req.url ?? "/", "http://x");
  const parts = url.pathname.split("/").filter(Boolean); // ["api", "servers", name?, action?]

  try {
    if (parts.length === 2 && req.method === "POST") return await createServer(req, res, store);

    const name = parts[2] ?? "";
    if (!NAME.test(name)) return send(res, 404, { error: "No existe ese servidor." });
    const server = store.servers().find((s) => s.metadata.name === name);
    if (!server) return send(res, 404, { error: "No existe ese servidor." });

    if (parts.length === 4 && parts[3] === "evaluate" && req.method === "POST") {
      if (server.spec.active === false) {
        return send(res, 409, { error: "El servidor está pausado: reanudalo para evaluarlo." });
      }
      await store.patch(name, { metadata: { annotations: { "security.eval.io/trigger-now": "true" } } });
      return send(res, 202, { ok: true });
    }
    if (parts.length === 4 && parts[3] === "pause" && req.method === "POST") {
      if (isGitManaged(server)) return send(res, 409, { error: "Este servidor se gestiona desde git: pausalo ahí." });
      const body = await readJson(req);
      if (typeof body["paused"] !== "boolean") return send(res, 400, { error: 'Mandá {"paused": true} o {"paused": false}.' });
      await store.patch(name, { spec: { active: !body["paused"] } });
      return send(res, 200, { ok: true });
    }
    if (parts.length === 3 && req.method === "DELETE") {
      if (isGitManaged(server)) return send(res, 409, { error: "Este servidor se gestiona desde git: borralo ahí." });
      await store.remove(name);
      return send(res, 200, { ok: true });
    }
    return send(res, 405, { error: "Acción no soportada." });
  } catch (err) {
    if (err instanceof SyntaxError || (err instanceof Error && /too large|not an object/.test(err.message))) {
      return send(res, 400, { error: "El pedido no es JSON válido." });
    }
    return send(res, 502, { error: `El cluster rechazó la acción: ${apiError(err)}` });
  }
}

async function createServer(req: IncomingMessage, res: ServerResponse, store: ServerStore): Promise<void> {
  if (!/^application\/json\b/.test(req.headers["content-type"] ?? "")) return send(res, 415, { error: "Mandá JSON." });
  const body = await readJson(req);
  const form: ServerForm = { ...EMPTY_FORM };
  for (const key of Object.keys(EMPTY_FORM) as (keyof ServerForm)[]) {
    const v = body[key];
    if (typeof v === "string") (form as unknown as Record<string, string>)[key] = v.trim();
  }
  const servers = store.servers();
  const errors = validateServerForm(form, servers.map((s) => s.metadata.name));
  if (Object.keys(errors).length > 0) return send(res, 400, { error: "Revisá los campos marcados.", fields: errors });
  if (servers.filter((s) => s.metadata.labels?.[LABEL_MANAGED_BY] === MANAGED_BY_UI).length >= MAX_UI_SERVERS) {
    return send(res, 429, { error: `Ya hay ${MAX_UI_SERVERS} servidores creados desde la UI. Borrá alguno antes de agregar otro.` });
  }
  const known = new Set(store.agentNames());
  const suite = DEFAULT_SUITE.filter((a) => known.has(a));
  if (suite.length === 0) return send(res, 503, { error: "No hay agentes de evaluación instalados en el cluster." });
  await store.create(serverFromForm(form, store.namespace, suite));
  send(res, 201, { name: form.name });
}
