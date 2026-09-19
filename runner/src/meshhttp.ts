/**
 * Mesh transport for the NetBird overlay (wt0) — HTTP client + local bridge.
 *
 * Evaluation pods run the NetBird client in USERSPACE mode
 * (NETBIRD_USERSPACE_HOSTWIRESOCK=yes): WireGuard is terminated in a
 * userspace netstack inside the `netbird` sidecar and exposed as a local
 * SOCKS5 proxy on 127.0.0.1:1080 (shared through the pod network namespace).
 * There is no wt0 interface in the pod and no kernel route, so application
 * traffic reaches the mesh explicitly:
 *
 *   - createMeshFetch(): fetch-style client for THIS process that dials
 *     SOCKS5 (or an HTTP proxy) for every request — used for the Vigil and
 *     Occludra calls.
 *
 *   - startMeshProxyBridge(): a tiny local HTTP proxy (absolute-form + CONNECT)
 *     that forwards into the same SOCKS5 proxy. The OpenCode server spawned by
 *     the SDK is a separate process we cannot teach to speak SOCKS5, so the
 *     evaluator points HTTP_PROXY/HTTPS_PROXY at the bridge and OpenCode's
 *     provider traffic (→ Occludra) traverses the mesh too.
 *
 * Only `http://` targets are supported for the plain request path — the mesh
 * data path is already WireGuard-encrypted, so in-cluster service traffic is
 * plain HTTP by design. An https:// target through the BRIDGE works via
 * CONNECT tunnelling (end-to-end TLS inside the tunnel).
 */

import * as http from "node:http";
import * as net from "node:net";
import { Logger, rootLogger } from "./logger.js";
import { ConfigurationError, MeshTransportError, errorMessage } from "./types.js";

const log: Logger = rootLogger.child("mesh");

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
// Bound for bridged upstream requests / CONNECT tunnels with no data flow.
// Matches the 10-minute ceiling Occludra applies to slow LLM completions.
const TUNNEL_IDLE_TIMEOUT_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// Proxy descriptor
// ---------------------------------------------------------------------------

export type ProxyScheme = "socks5" | "http";

export interface ProxyDescriptor {
  scheme: ProxyScheme;
  host: string;
  port: number;
  username?: string;
  password?: string;
}

/** Parse `socks5://[user:pass@]host:port` / `http://...` (socks5h accepted as socks5). */
export function parseProxyUrl(raw: string): ProxyDescriptor {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch (err) {
    throw new ConfigurationError(`mesh proxy URL is not parseable: ${errorMessage(err)}`);
  }
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "socks5" && scheme !== "socks5h" && scheme !== "http") {
    throw new ConfigurationError(`mesh proxy scheme must be socks5, socks5h or http, got "${scheme}"`);
  }
  const portRaw = parsed.port ? Number.parseInt(parsed.port, 10) : scheme === "http" ? 80 : 1080;
  if (!Number.isFinite(portRaw) || portRaw <= 0 || portRaw > 65535) {
    throw new ConfigurationError(`mesh proxy port is invalid in "${raw}"`);
  }
  const username = parsed.username ? decodeURIComponent(parsed.username) : undefined;
  const password = parsed.password ? decodeURIComponent(parsed.password) : undefined;
  return {
    scheme: scheme === "http" ? "http" : "socks5",
    host: parsed.hostname,
    port: portRaw,
    username: username !== "" ? username : undefined,
    password: password !== "" ? password : undefined,
  };
}

function assertHttpTarget(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new ConfigurationError(`mesh target URL is not parseable: ${errorMessage(err)}`);
  }
  if (parsed.protocol !== "http:") {
    throw new ConfigurationError(
      `mesh target must be http:// (the WireGuard tunnel provides encryption); got "${parsed.protocol}"`,
    );
  }
  if (parsed.hostname.includes(":")) {
    throw new ConfigurationError(`mesh target host must be a name or IPv4 literal, got "${parsed.hostname}"`);
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// SOCKS5 (RFC 1928) client — the NetBird userspace proxy dialect
// ---------------------------------------------------------------------------

type SocksStage = "greeting" | "auth" | "connect";

const SOCKS_SUCCESS = 0x00;

function socksGreeting(proxy: ProxyDescriptor): Buffer {
  return proxy.username !== undefined && proxy.password !== undefined
    ? Buffer.from([0x05, 0x02, 0x00, 0x02])
    : Buffer.from([0x05, 0x01, 0x00]);
}

function socksAuthRequest(proxy: ProxyDescriptor): Buffer {
  const user = Buffer.from(proxy.username ?? "", "utf8");
  const pass = Buffer.from(proxy.password ?? "", "utf8");
  return Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]);
}

/** CONNECT with ATYP=domain: the PROXY resolves the mesh DNS name. */
function socksConnectRequest(host: string, port: number): Buffer {
  const hostBuf = Buffer.from(host, "utf8");
  const head = Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]);
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port);
  return Buffer.concat([head, hostBuf, portBuf]);
}

function socksDescribeReply(rep: number): string {
  const reasons: Record<number, string> = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset (NetBird ACL denied the destination?)",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
  };
  return reasons[rep] ?? `unknown reply 0x${rep.toString(16)}`;
}

/**
 * Dial `host:port` through a SOCKS5 proxy and resolve with the connected
 * socket. Handles greeting, optional username/password auth, and the CONNECT
 * round-trip (buffered — replies may arrive split across TCP segments).
 */
export function socks5Connect(proxy: ProxyDescriptor, host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise<net.Socket>((resolve, reject) => {
    const socket = net.connect({ host: proxy.host, port: proxy.port });
    socket.setTimeout(timeoutMs);
    let stage: SocksStage = "greeting";
    let buf: Buffer = Buffer.alloc(0);
    let settled = false;

    const fail = (message: string): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new MeshTransportError(`SOCKS5 ${stage} via ${proxy.host}:${proxy.port} failed: ${message}`));
    };

    socket.on("error", (err: Error) => fail(errorMessage(err)));
    socket.on("timeout", () => fail(`timed out after ${timeoutMs}ms in stage "${stage}"`));
    socket.on("close", () => {
      if (!settled) fail("connection closed before the SOCKS5 handshake completed");
    });

    socket.on("connect", () => {
      socket.write(socksGreeting(proxy));
    });

    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      try {
        // Loop because one TCP segment may carry more than one reply.
        for (;;) {
          if (stage === "greeting") {
            if (buf.length < 2) return;
            const version = buf[0] ?? 0;
            const method = buf[1] ?? 0xff;
            buf = buf.subarray(2);
            if (version !== 0x05) {
              fail(`unexpected protocol version 0x${version.toString(16)}`);
              return;
            }
            if (method === 0x00) {
              stage = "connect";
              socket.write(socksConnectRequest(host, port));
            } else if (method === 0x02 && proxy.username !== undefined) {
              stage = "auth";
              socket.write(socksAuthRequest(proxy));
            } else {
              fail(`proxy requires an unsupported auth method 0x${method.toString(16)}`);
              return;
            }
            continue;
          }
          if (stage === "auth") {
            if (buf.length < 2) return;
            const version = buf[0] ?? 0;
            const status = buf[1] ?? 0xff;
            buf = buf.subarray(2);
            if (version !== 0x01 || status !== SOCKS_SUCCESS) {
              fail(`username/password authentication rejected (status 0x${status.toString(16)})`);
              return;
            }
            stage = "connect";
            socket.write(socksConnectRequest(host, port));
            continue;
          }
          // stage === "connect": 4-byte head + variable-length address.
          if (buf.length < 5) return;
          const version = buf[0] ?? 0;
          const rep = buf[1] ?? 0xff;
          const atyp = buf[3] ?? 0xff;
          if (version !== 0x05) {
            fail(`unexpected protocol version 0x${version.toString(16)} in CONNECT reply`);
            return;
          }
          let replyLen: number;
          if (atyp === 0x01) replyLen = 4 + 4 + 2;
          else if (atyp === 0x04) replyLen = 4 + 16 + 2;
          else if (atyp === 0x03) replyLen = 4 + 1 + (buf[4] ?? 0) + 2;
          else {
            fail(`unexpected address type 0x${atyp.toString(16)} in CONNECT reply`);
            return;
          }
          if (buf.length < replyLen) return;
          buf = buf.subarray(replyLen);
          if (rep !== SOCKS_SUCCESS) {
            fail(socksDescribeReply(rep));
            return;
          }
          // Connected: hand the socket over and disable the handshake timeout.
          // The earlier "close" handler is a no-op now (guarded by `settled`).
          settled = true;
          socket.setTimeout(0);
          resolve(socket);
          return;
        }
      } catch (err) {
        fail(errorMessage(err));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// HTTP over a socket / proxy
// ---------------------------------------------------------------------------

export interface MeshRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeoutMs?: number;
}

/** Minimal response surface — enough for the JSON APIs the runner consumes. */
export interface MeshResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  text(): string;
  json<T = unknown>(): T;
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function sanitizeRequestHeaders(
  headers: Record<string, string | string[] | undefined> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (v === undefined || HOP_BY_HOP.has(k.toLowerCase())) {
      continue;
    }
    out[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

function collectResponse(req: http.ClientRequest, timeoutMs: number): Promise<MeshResponse> {
  return new Promise<MeshResponse>((resolve, reject) => {
    const timer = setTimeout(() => {
      req.destroy(new MeshTransportError(`response timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    req.once("response", (res: http.IncomingMessage) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          res.destroy(new MeshTransportError(`response exceeds ${MAX_RESPONSE_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        clearTimeout(timer);
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (typeof v === "string") headers[k] = v;
          else if (Array.isArray(v)) headers[k] = v.join(", ");
        }
        const body = Buffer.concat(chunks);
        resolve({
          status: res.statusCode ?? 0,
          headers,
          body,
          text: () => body.toString("utf8"),
          json: <T,>() => JSON.parse(body.toString("utf8")) as T,
        });
      });
      res.on("error", (err: Error) => {
        clearTimeout(timer);
        reject(new MeshTransportError(`response stream failed: ${errorMessage(err)}`));
      });
    });
    req.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err instanceof MeshTransportError ? err : new MeshTransportError(errorMessage(err)));
    });
  });
}

async function requestViaSocks(
  proxy: ProxyDescriptor,
  target: URL,
  init: MeshRequestInit,
  timeoutMs: number,
): Promise<MeshResponse> {
  const port = target.port ? Number.parseInt(target.port, 10) : 80;
  const socket = await socks5Connect(proxy, target.hostname, port, timeoutMs);
  try {
    const headers = sanitizeRequestHeaders(init.headers);
    headers["host"] = target.host;
    const req = http.request({
      host: target.hostname,
      port,
      path: `${target.pathname}${target.search}`,
      method: init.method ?? "GET",
      headers,
      createConnection: () => socket,
    });
    const responsePromise = collectResponse(req, timeoutMs);
    if (init.body !== undefined) req.end(init.body);
    else req.end();
    return await responsePromise;
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

async function requestViaHttpProxy(
  proxy: ProxyDescriptor,
  target: URL,
  init: MeshRequestInit,
  timeoutMs: number,
): Promise<MeshResponse> {
  const headers = sanitizeRequestHeaders(init.headers);
  headers["host"] = target.host;
  if (proxy.username !== undefined) {
    const cred = Buffer.from(`${proxy.username}:${proxy.password ?? ""}`, "utf8").toString("base64");
    headers["proxy-authorization"] = `Basic ${cred}`;
  }
  const proxyPort = proxy.port;
  const req = http.request({
    host: proxy.host,
    port: proxyPort,
    // Absolute-form request: the proxy is the outbound dialer.
    path: target.toString(),
    method: init.method ?? "GET",
    headers,
  });
  const responsePromise = collectResponse(req, timeoutMs);
  if (init.body !== undefined) req.end(init.body);
  else req.end();
  return await responsePromise;
}

async function requestDirect(target: URL, init: MeshRequestInit, timeoutMs: number): Promise<MeshResponse> {
  const port = target.port ? Number.parseInt(target.port, 10) : 80;
  const req = http.request({
    host: target.hostname,
    port,
    path: `${target.pathname}${target.search}`,
    method: init.method ?? "GET",
    headers: sanitizeRequestHeaders(init.headers),
  });
  const responsePromise = collectResponse(req, timeoutMs);
  if (init.body !== undefined) req.end(init.body);
  else req.end();
  return await responsePromise;
}

export type MeshFetch = (url: string, init?: MeshRequestInit) => Promise<MeshResponse>;

/**
 * Poll the local mesh proxy (the netbird userspace sidecar's SOCKS5 listener)
 * with plain TCP dials until it accepts connections, so the first real Vigil /
 * Occludra call does not die against a sidecar that is still enrolling.
 * Throws MeshTransportError if the proxy never comes up within timeoutMs.
 */
export async function waitForSocks5Proxy(rawProxy: string, timeoutMs: number, intervalMs = 1000): Promise<void> {
  const proxy = parseProxyUrl(rawProxy);
  const deadline = Date.now() + timeoutMs;
  for (let attempt = 1; ; attempt++) {
    const up = await new Promise<boolean>((resolve) => {
      const socket = net.connect({ host: proxy.host, port: proxy.port });
      const done = (ok: boolean): void => {
        socket.destroy();
        resolve(ok);
      };
      socket.setTimeout(Math.min(intervalMs, 2000), () => done(false));
      socket.once("connect", () => done(true));
      socket.once("error", () => done(false));
    });
    if (up) {
      log.info("mesh proxy is accepting connections", { proxy: `${proxy.host}:${proxy.port}`, attempt });
      return;
    }
    if (Date.now() >= deadline) {
      throw new MeshTransportError(
        `mesh proxy ${proxy.host}:${proxy.port} did not come up within ${timeoutMs}ms — ` +
          `check the netbird sidecar logs (enrollment may have failed)`,
      );
    }
    if (attempt % 10 === 0) {
      log.info("waiting for mesh proxy", { proxy: `${proxy.host}:${proxy.port}`, waitedMs: Date.now() - (deadline - timeoutMs) });
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/**
 * Build the mesh-aware fetch used for Vigil / Occludra calls.
 * `rawProxy === null | ""` → direct connections (non-mesh fallback mode).
 */
export function createMeshFetch(rawProxy: string | null, defaultTimeoutMs = DEFAULT_TIMEOUT_MS): MeshFetch {
  const proxy = rawProxy !== null && rawProxy !== "" ? parseProxyUrl(rawProxy) : null;
  return async (url, init = {}) => {
    const target = assertHttpTarget(url);
    const timeoutMs = init.timeoutMs ?? defaultTimeoutMs;
    if (proxy === null) {
      return requestDirect(target, init, timeoutMs);
    }
    if (proxy.scheme === "socks5") {
      return requestViaSocks(proxy, target, init, timeoutMs);
    }
    return requestViaHttpProxy(proxy, target, init, timeoutMs);
  };
}

// ---------------------------------------------------------------------------
// Local HTTP proxy bridge (for the OpenCode child process)
// ---------------------------------------------------------------------------

export interface MeshBridge {
  /** e.g. http://127.0.0.1:18080 — set as HTTP_PROXY/HTTPS_PROXY for children. */
  url: string;
  port: number;
  close(): Promise<void>;
}

interface BridgeOptions {
  host?: string;
  port?: number;
  timeoutMs?: number;
}

function pipeSockets(a: net.Socket, b: net.Socket): void {
  const teardown = (): void => {
    a.destroy();
    b.destroy();
  };
  // A CONNECT tunnel through a hung netbird can otherwise stall forever:
  // tear tunnels down after TUNNEL_IDLE_TIMEOUT_MS without data flowing in
  // either direction (LLM SSE streams flush at least every few seconds).
  let lastActivity = Date.now();
  const touch = (): void => {
    lastActivity = Date.now();
  };
  a.on("data", touch);
  b.on("data", touch);
  const idleTimer = setInterval(() => {
    if (Date.now() - lastActivity >= TUNNEL_IDLE_TIMEOUT_MS) teardown();
  }, 30_000);
  idleTimer.unref();
  const onDone = (): void => {
    clearInterval(idleTimer);
    teardown();
  };
  a.on("close", onDone);
  b.on("close", onDone);
  a.on("error", onDone);
  b.on("error", onDone);
  a.pipe(b);
  b.pipe(a);
}

/**
 * Start a localhost-only HTTP proxy that forwards every request into the
 * mesh proxy (SOCKS5 → NetBird). Handles:
 *   - absolute-form `GET http://occludra.../v1/...` requests (HTTP clients
 *     honouring HTTP_PROXY for plain-HTTP targets), and
 *   - `CONNECT host:port` tunnels (HTTPS targets), piped raw through the mesh.
 */
export async function startMeshProxyBridge(rawProxy: string, opts: BridgeOptions = {}): Promise<MeshBridge> {
  const proxy = parseProxyUrl(rawProxy);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const host = opts.host ?? "127.0.0.1";
  const requestedPort = opts.port ?? 18080;

  const server = http.createServer((req, res) => {
    const target = req.url ?? "";
    let parsed: URL;
    try {
      parsed = new URL(target);
    } catch {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("mesh bridge: malformed absolute-form request URL");
      return;
    }
    if (parsed.protocol !== "http:") {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("mesh bridge: only http:// absolute-form targets are supported");
      return;
    }
    const port = parsed.port ? Number.parseInt(parsed.port, 10) : 80;
    const send = (code: number, message: string): void => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(code, { "content-type": "text/plain", "proxy-agent": "mcp-eval-mesh-bridge" });
      res.end(message);
    };
    const dial = (): Promise<net.Socket> =>
      proxy.scheme === "socks5"
        ? socks5Connect(proxy, parsed.hostname, port, timeoutMs)
        : new Promise<net.Socket>((resolve, reject) => {
            const upstream = net.connect({ host: proxy.host, port: proxy.port });
            upstream.setTimeout(timeoutMs, () => upstream.destroy(new Error("HTTP proxy dial timed out")));
            upstream.on("connect", () => resolve(upstream));
            upstream.on("error", (err: Error) => reject(new MeshTransportError(errorMessage(err))));
          });

    log.debug("bridge request", { target: parsed.host, method: req.method });
    dial()
      .then((upstream) => {
        const headers = sanitizeRequestHeaders({ ...req.headers });
        headers["host"] = parsed.host;
        if (proxy.scheme === "http" && proxy.username !== undefined) {
          const cred = Buffer.from(`${proxy.username}:${proxy.password ?? ""}`, "utf8").toString("base64");
          headers["proxy-authorization"] = `Basic ${cred}`;
        }
        const ureq = http.request({
          host: parsed.hostname,
          port,
          path: parsed.toString(),
          method: req.method ?? "GET",
          headers,
          createConnection: () => upstream,
        });
        // No inactivity bound on the absolute-form path otherwise: a hung
        // upstream would stall this bridge request forever.
        ureq.setTimeout(TUNNEL_IDLE_TIMEOUT_MS, () => {
          ureq.destroy(new MeshTransportError(`upstream inactivity timeout after ${TUNNEL_IDLE_TIMEOUT_MS}ms`));
        });
        ureq.on("response", (ures: http.IncomingMessage) => {
          if (res.headersSent) {
            ures.destroy();
            return;
          }
          const outHeaders: Record<string, string> = {};
          for (const [name, value] of Object.entries(ures.headers)) {
            if (value === undefined || HOP_BY_HOP.has(name.toLowerCase())) continue;
            outHeaders[name] = Array.isArray(value) ? value.join(", ") : value;
          }
          res.writeHead(ures.statusCode ?? 502, outHeaders);
          ures.pipe(res);
        });
        ureq.on("error", (err: Error) => {
          send(502, `mesh bridge upstream error: ${errorMessage(err)}`);
          upstream.destroy();
        });
        req.pipe(ureq);
        req.on("error", () => ureq.destroy());
      })
      .catch((err: unknown) => {
        log.warn("bridge dial failed", { target: parsed.host, error: errorMessage(err) });
        send(502, `mesh bridge dial failed: ${errorMessage(err)}`);
      });
  });

  // CONNECT: establish the tunnel first, reply 200, then raw-pipe.
  server.on("connect", (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
    const target = req.url ?? "";
    const sep = target.lastIndexOf(":");
    if (sep <= 0) {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    const hostname = target.slice(0, sep);
    const port = Number.parseInt(target.slice(sep + 1), 10);
    if (!Number.isFinite(port) || port <= 0 || port > 65535) {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    const dial = (): Promise<net.Socket> =>
      proxy.scheme === "socks5"
        ? socks5Connect(proxy, hostname, port, timeoutMs)
        : new Promise<net.Socket>((resolve, reject) => {
            // Chain CONNECT through an upstream HTTP proxy.
            const upstream = net.connect({ host: proxy.host, port: proxy.port });
            upstream.setTimeout(timeoutMs, () => upstream.destroy(new Error("HTTP proxy CONNECT timed out")));
            upstream.on("error", (err: Error) => reject(new MeshTransportError(errorMessage(err))));
            upstream.on("connect", () => {
              let reqLine = `CONNECT ${hostname}:${port} HTTP/1.1\r\nhost: ${hostname}:${port}\r\n`;
              if (proxy.username !== undefined) {
                const cred = Buffer.from(`${proxy.username}:${proxy.password ?? ""}`, "utf8").toString("base64");
                reqLine += `proxy-authorization: Basic ${cred}\r\n`;
              }
              upstream.write(`${reqLine}\r\n`);
            });
            let buf = Buffer.alloc(0);
            const onData = (chunk: Buffer): void => {
              buf = Buffer.concat([buf, chunk]);
              const end = buf.indexOf("\r\n\r\n");
              if (end === -1) return;
              upstream.removeListener("data", onData);
              const statusLine = buf.subarray(0, buf.indexOf("\r\n")).toString("utf8");
              if (/\s2\d\d(\s|$)/.test(statusLine)) {
                const surplus = buf.subarray(end + 4);
                resolve(upstream);
                if (surplus.length > 0) clientSocket.write(surplus);
              } else {
                reject(new MeshTransportError(`upstream HTTP proxy refused CONNECT: ${statusLine}`));
              }
            };
            upstream.on("data", onData);
          });

    dial()
      .then((remote) => {
        clientSocket.write("HTTP/1.1 200 Connection established\r\n\r\n");
        if (head.length > 0) remote.write(head);
        pipeSockets(clientSocket, remote);
      })
      .catch((err: unknown) => {
        log.warn("bridge CONNECT failed", { target, error: errorMessage(err) });
        clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\n\r\n${errorMessage(err)}`);
      });
  });

  server.on("clientError", (err: Error, socket: net.Socket) => {
    log.debug("bridge client error", { error: errorMessage(err) });
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  });

  return await new Promise<MeshBridge>((resolve, reject) => {
    const onError = (err: Error & { code?: string }): void => {
      if (err.code === "EADDRINUSE" && requestedPort !== 0) {
        log.warn("mesh bridge port busy; falling back to an ephemeral port", { port: requestedPort });
        server.listen({ host, port: 0, exclusive: true });
        return;
      }
      reject(new ConfigurationError(`mesh bridge failed to listen: ${errorMessage(err)}`));
    };
    server.once("error", onError);
    server.on("listening", () => {
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : requestedPort;
      log.info("mesh bridge listening", { host, port, upstream: `${proxy.scheme}://${proxy.host}:${proxy.port}` });
      resolve({
        port,
        url: `http://${host}:${port}`,
        close: async () => {
          await new Promise<void>((res) => server.close(() => res()));
          server.closeAllConnections();
        },
      });
    });
    server.listen({ host, port: requestedPort, exclusive: true });
  });
}
