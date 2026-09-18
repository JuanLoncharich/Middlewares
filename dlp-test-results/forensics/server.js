const http = require("http");
const fs = require("fs");
const LOG = "/tmp/cap/log.jsonl";
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    let parsed = null;
    try { parsed = body ? JSON.parse(body) : null; } catch { parsed = body; }
    const rec = {
      ts: new Date().toISOString(),
      method: req.method,
      url: req.url,
      httpVersion: req.httpVersion,
      headers: req.headers,
      body: parsed
    };
    fs.appendFileSync(LOG, JSON.stringify(rec) + "\n");
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "capture-only" }));
  });
});
server.listen(9999, "127.0.0.1", () => console.log("capture server on 127.0.0.1:9999"));
