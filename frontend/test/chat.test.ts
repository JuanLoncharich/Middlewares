import { type AddressInfo } from "node:net";
import { type Server, createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ChatReply } from "../src/model/chat.ts";

// A fake OpenCode server and a fake Occludra journal; chat.ts reads its env
// at import, so the module is loaded after both are listening.
const seen: { path: string; body: unknown }[] = [];
let journalEntries: unknown[] = [];

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

const opencode = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    seen.push({ path: req.url ?? "", body: body ? JSON.parse(body) : null });
    res.setHeader("content-type", "application/json");
    if (req.url === "/session") return res.end(JSON.stringify({ id: "ses_abcdefgh12345678" }));
    journalEntries.push({ id: journalEntries.length + 1, client: "ui-chat", redactions: { email: 1 }, status: 200, durationMs: 900, requestBytes: 700, responseBytes: 300, upstream: "10.147.17.21:8080", at: "", servedBy: "primary" });
    res.end(
      JSON.stringify({
        info: { providerID: "local", modelID: "lfm2.5-24b-a2b", tokens: { input: 40, output: 12 }, time: { created: 1, completed: 1001 } },
        parts: [{ type: "step-start" }, { type: "text", text: "Hola." }],
      }),
    );
  });
});

const occludra = createServer((req, res) => {
  const after = Number(new URL(req.url ?? "/", "http://x").searchParams.get("after") ?? 0);
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ entries: journalEntries.filter((e) => (e as { id: number }).id > after) }));
});

let ui: Server;
let base = "";

beforeAll(async () => {
  process.env["CHAT_URL"] = await listen(opencode);
  process.env["OCCLUDRA_INSPECT_URL"] = await listen(occludra);
  const { handleChat, setRunContext } = await import("../server/chat.ts");
  setRunContext((run) => (run === "weather-run-1" ? "<datos>veredicto Malicious</datos>" : null));
  ui = createServer((req, res) => void handleChat(req, res));
  base = await listen(ui);
});

afterAll(() => {
  for (const s of [opencode, occludra, ui]) s.close();
});

function post(body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${base}/api/chat`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("POST /api/chat", () => {
  it("asks OpenCode without tools and reports only this message's model calls", async () => {
    journalEntries = [{ id: 1, client: "ui-chat", redactions: {}, status: 200 }]; // an older call
    const res = await post({ text: "mi mail es ana@example.com" });
    expect(res.status).toBe(200);
    const reply = (await res.json()) as ChatReply;
    expect(reply.text).toBe("Hola.");
    expect(reply.session).toBe("ses_abcdefgh12345678");
    expect(reply.gateway?.map((g) => g.id)).toEqual([2]);
    expect(reply.gateway?.[0]?.redactions).toEqual({ email: 1 });
    expect(reply.opencodeMs).toBe(1000);
    const message = seen.find((s) => s.path.endsWith("/message"))!.body as { tools: object; model: object };
    expect(message.tools).toEqual({});
    expect(message.model).toEqual({ providerID: "local", modelID: "lfm2.5-24b-a2b" });
  });

  it("reuses the session the browser sends", async () => {
    seen.length = 0;
    await post({ text: "otra", session: "ses_abcdefgh12345678" });
    expect(seen.map((s) => s.path)).toEqual(["/session/ses_abcdefgh12345678/message"]);
  });

  it("refuses other origins, bad input and malformed sessions", async () => {
    expect((await post({ text: "hola" }, { origin: "https://evil.example" })).status).toBe(403);
    expect((await post({ text: "" })).status).toBe(400);
    expect((await post({ text: "x".repeat(4001) })).status).toBe(400);
    seen.length = 0;
    await post({ text: "hola", session: "../../etc" });
    expect(seen[0]?.path).toBe("/session"); // ignored, a new one is created
  });

  it("opens a run's session with its data, then asks plainly", async () => {
    seen.length = 0;
    const first = (await (await post({ text: "¿por qué?", run: "weather-run-1" })).json()) as ChatReply;
    await post({ text: "¿y ahora?", run: "weather-run-1", session: first.session });
    const messages = seen.filter((s) => s.path.endsWith("/message")).map((s) => (s.body as { parts: { text: string }[] }).parts[0]!.text);
    expect(messages[0]).toBe("<datos>veredicto Malicious</datos>\n\nPregunta: ¿por qué?");
    expect(messages[1]).toBe("¿y ahora?");
    expect((await post({ text: "hola", run: "no-such-run" })).status).toBe(404);
  });
});
