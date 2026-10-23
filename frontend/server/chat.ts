// POST /api/chat: one message to the in-cluster OpenCode server, plus what
// Occludra did with the model calls it caused. OpenCode runs with every tool
// denied and its only provider pinned to Occludra (frontend/deploy/ui-chat.yaml),
// so the answer comes from the local LFM through the same egress gateway the
// evaluations use. Occludra's journal (images/occludra-gateway/journal.go)
// holds metadata only: redaction counts, status, timing, sizes.
//
// Env: CHAT_URL (OpenCode server; chat is off when unset), CHAT_MODEL
// (provider/model, default local/lfm2.5-24b-a2b), OCCLUDRA_INSPECT_URL
// (journal base URL, optional), OPENCODE_SERVER_PASSWORD (optional basic auth).
import type { IncomingMessage, ServerResponse } from "node:http";
import { isSameOrigin } from "./origin.ts";
import type { ChatReply, GatewayHop } from "../src/model/chat.ts";

const CHAT_URL = (process.env["CHAT_URL"] ?? "").replace(/\/$/, "");
const CHAT_MODEL = process.env["CHAT_MODEL"] ?? "local/lfm2.5-24b-a2b";
const INSPECT_URL = (process.env["OCCLUDRA_INSPECT_URL"] ?? "").replace(/\/$/, "");
const PASSWORD = process.env["OPENCODE_SERVER_PASSWORD"] ?? "";
const CLIENT = "ui-chat";
const MAX_TEXT = 4000;
const MAX_BODY = 16 * 1024;
const ANSWER_TIMEOUT_MS = 5 * 60_000;
const SESSION_ID = /^ses_[A-Za-z0-9]{8,64}$/;

export const chatEnabled = CHAT_URL !== "";

// The model is one GPU: one message at a time, for everyone.
let busy = false;

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
}

function opencodeHeaders(): Record<string, string> {
  const h: Record<string, string> = { "content-type": "application/json" };
  if (PASSWORD) h["authorization"] = `Basic ${Buffer.from(`opencode:${PASSWORD}`).toString("base64")}`;
  return h;
}

async function readBody(req: IncomingMessage): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function journal(after: number): Promise<GatewayHop[] | null> {
  if (!INSPECT_URL) return null;
  try {
    const res = await fetch(`${INSPECT_URL}/requests?client=${CLIENT}&after=${after}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const body = (await res.json()) as { entries?: GatewayHop[] };
    return body.entries ?? [];
  } catch {
    return null;
  }
}

async function journalCursor(): Promise<number> {
  const entries = await journal(0);
  return entries?.reduce((max, e) => Math.max(max, e.id), 0) ?? 0;
}

async function newSession(): Promise<string> {
  const res = await fetch(`${CHAT_URL}/session`, {
    method: "POST",
    headers: opencodeHeaders(),
    body: JSON.stringify({ title: CLIENT }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`OpenCode no creó la sesión (HTTP ${res.status})`);
  const body = (await res.json()) as { id?: string };
  if (!body.id || !SESSION_ID.test(body.id)) throw new Error("OpenCode devolvió una sesión inválida");
  return body.id;
}

interface OpencodePart {
  type: string;
  text?: string;
}

interface OpencodeAnswer {
  info?: {
    modelID?: string;
    providerID?: string;
    tokens?: { input?: number; output?: number };
    time?: { created?: number; completed?: number };
    error?: { name?: string; data?: { message?: string } };
  };
  parts?: OpencodePart[];
}

export async function handleChat(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!chatEnabled) return send(res, 503, { error: "El chat no está configurado en este servidor (falta CHAT_URL)." });
  if (req.method !== "POST") return send(res, 405, { error: "Usá POST." });
  // Same reason as the WebSocket: no other site may drive this chat through
  // a local `npm run live` or a port-forward.
  if (!isSameOrigin(req.headers.origin, req.headers.host)) return send(res, 403, { error: "Origen no permitido." });
  if (!/^application\/json\b/.test(req.headers["content-type"] ?? "")) return send(res, 415, { error: "Mandá JSON." });

  let input: { session?: unknown; text?: unknown };
  try {
    input = JSON.parse(await readBody(req)) as typeof input;
  } catch {
    return send(res, 400, { error: "El pedido no es JSON válido." });
  }
  const text = typeof input.text === "string" ? input.text.trim() : "";
  if (!text || text.length > MAX_TEXT) return send(res, 400, { error: `Escribí entre 1 y ${MAX_TEXT} caracteres.` });
  const requested = typeof input.session === "string" && SESSION_ID.test(input.session) ? input.session : null;

  if (busy) return send(res, 429, { error: "El modelo está respondiendo otra pregunta. Probá en unos segundos." });
  busy = true;
  const started = Date.now();
  try {
    const cursor = await journalCursor();
    const session = requested ?? (await newSession());
    const [providerID, ...rest] = CHAT_MODEL.split("/");
    const modelID = rest.join("/");
    const answerRes = await fetch(`${CHAT_URL}/session/${session}/message`, {
      method: "POST",
      headers: opencodeHeaders(),
      body: JSON.stringify({ model: { providerID, modelID }, tools: {}, parts: [{ type: "text", text }] }),
      signal: AbortSignal.timeout(ANSWER_TIMEOUT_MS),
    });
    if (answerRes.status === 404 && requested) {
      // OpenCode restarted and forgot the session; the browser starts over.
      return send(res, 409, { error: "La conversación se reinició del lado del servidor. Volvé a mandar el mensaje.", resetSession: true });
    }
    if (!answerRes.ok) throw new Error(`OpenCode respondió HTTP ${answerRes.status}`);
    const answer = (await answerRes.json()) as OpencodeAnswer;
    const totalMs = Date.now() - started;
    const hops = await journal(cursor);
    const info = answer.info ?? {};
    const reply: ChatReply = {
      session,
      text: (answer.parts ?? [])
        .filter((p) => p.type === "text" && p.text)
        .map((p) => p.text)
        .join("\n")
        .trim(),
      error: info.error ? (info.error.data?.message ?? info.error.name ?? "error") : undefined,
      model: info.providerID && info.modelID ? `${info.providerID}/${info.modelID}` : CHAT_MODEL,
      tokens: { input: info.tokens?.input ?? 0, output: info.tokens?.output ?? 0 },
      totalMs,
      opencodeMs: info.time?.created && info.time.completed ? info.time.completed - info.time.created : undefined,
      gateway: hops,
    };
    send(res, 200, reply);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const down = /fetch failed|ECONNREFUSED|ENOTFOUND|timeout/i.test(message);
    send(res, 502, {
      error: down
        ? "No se pudo hablar con OpenCode o con el modelo. ¿Está prendido el LFM en la PC?"
        : `Falló la consulta: ${message}`,
    });
  } finally {
    busy = false;
  }
}
