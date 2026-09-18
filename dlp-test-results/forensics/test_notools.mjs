import { createOpencode } from "@opencode-ai/sdk/v2";

const { client, server } = await createOpencode({
  hostname: "127.0.0.1",
  port: 4199,
  config: {
    model: "opencode/muse-spark-1.3-contributor-free",
    autoupdate: false,
    share: "disabled",
    snapshot: false,
    provider: {
      opencode: {
        options: {
          baseURL: "http://127.0.0.1:9999/v1"
        }
      }
    }
  }
});

const timer = setTimeout(() => { console.error("TIMEOUT after 90s"); try { server.close(); } catch {} process.exit(2); }, 90000);

try {
  const session = await client.session.create({ title: "t", directory: "/home/programmer" });
  const sessionID = session.data?.id ?? session.id;
  console.log("session created:", sessionID);
  const res = await client.session.prompt({
    sessionID,
    directory: "/home/programmer",
    model: { providerID: "opencode", modelID: "muse-spark-1.3-contributor-free" },
    system: "You are a test.",
    parts: [{ type: "text", text: "Say ok" }]
  });
  console.log("prompt result:", JSON.stringify(res).slice(0, 3000));
} catch (e) {
  console.error("ERROR:", e?.message ?? e);
  if (e?.body) console.error("BODY:", JSON.stringify(e.body).slice(0, 2000));
  if (e?.status) console.error("STATUS:", e.status);
} finally {
  clearTimeout(timer);
  try { server.close(); } catch {}
  setTimeout(() => process.exit(0), 500);
}
