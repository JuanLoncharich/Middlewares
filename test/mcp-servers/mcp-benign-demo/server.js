/**
 * mcp-benign-demo — a deliberately UNREMARKABLE MCP stdio server.
 *
 * Test fixture for the evaluation platform's happy path: clean tool
 * descriptions, honest outputs, no instructions addressed to the model, no
 * network calls, no filesystem access beyond what the caller sends.
 *
 * Zero dependencies on purpose (plain Node) so the in-cluster git fixture
 * never needs an npm registry at clone time.
 */

const SERVER_INFO = { name: "mcp-benign-demo", version: "1.0.0" };

const TOOLS = [
  {
    name: "add",
    description: "Add two numbers and return the sum.",
    inputSchema: {
      type: "object",
      properties: { a: { type: "number" }, b: { type: "number" } },
      required: ["a", "b"],
    },
  },
  {
    name: "now",
    description: "Return the current server time in ISO-8601 (UTC).",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "reverse",
    description: "Reverse the characters of the provided text.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"],
    },
  },
];

function toolCall(name, args) {
  if (name === "add") {
    const a = Number(args?.a ?? 0);
    const b = Number(args?.b ?? 0);
    if (!Number.isFinite(a) || !Number.isFinite(b)) {
      return { isError: true, content: [{ type: "text", text: "a and b must be numbers" }] };
    }
    return { content: [{ type: "text", text: String(a + b) }] };
  }
  if (name === "now") {
    return { content: [{ type: "text", text: new Date().toISOString() }] };
  }
  if (name === "reverse") {
    const text = String(args?.text ?? "");
    return { content: [{ type: "text", text: [...text].reverse().join("") }] };
  }
  return { isError: true, content: [{ type: "text", text: `unknown tool: ${name}` }] };
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (line) handle(line);
  }
});

function handle(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  const { id, method, params } = msg ?? {};
  switch (method) {
    case "initialize":
      send(id, {
        protocolVersion: params?.protocolVersion ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });
      break;
    case "tools/list":
      send(id, { tools: TOOLS });
      break;
    case "tools/call":
      send(id, toolCall(params?.name, params?.arguments));
      break;
    default:
      if (id !== undefined) {
        send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
      }
  }
}

function send(id, result) {
  if (id === undefined) return; // notifications get no reply
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
