#!/usr/bin/env python3
"""Minimal git smart-HTTP server for the local evaluation test fixtures.

Bridges git's CGI `git-http-backend` to http.server (ThreadingHTTPServer) and
wraps everything in TLS. Smart HTTP is required because the platform's cloner
clones with `--depth 1`, which the dumb HTTP transport does not support.
Bodies are fully buffered — fixture repos are a few KB, this is a TEST DOUBLE
in the same spirit as images/vigil-stub, not a production git host.
"""

import functools
import os
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPOS = os.environ.get("GIT_REPOS_ROOT", "/repos")
BACKEND = os.environ.get(
    "GIT_HTTP_BACKEND", "/usr/libexec/git-core/git-http-backend"
)
PORT = int(os.environ.get("GIT_SERVER_PORT", "5443"))
TLS_CERT = os.environ.get("GIT_SERVER_TLS_CERT", "")
TLS_KEY = os.environ.get("GIT_SERVER_TLS_KEY", "")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _backend(self):
        path, _, query = self.path.partition("?")
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        env = {
            "GIT_PROJECT_ROOT": REPOS,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": path,
            "REQUEST_METHOD": self.command,
            "QUERY_STRING": query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_ADDR": self.client_address[0],
            "SERVER_PROTOCOL": "HTTP/1.1",
        }
        git_protocol = self.headers.get("Git-Protocol")
        if git_protocol:
            env["HTTP_GIT_PROTOCOL"] = git_protocol
        proc = subprocess.run([BACKEND], env=env, input=body, capture_output=True)
        head, sep, payload = proc.stdout.partition(b"\r\n\r\n")
        if not sep:
            head, sep, payload = proc.stdout.partition(b"\n\n")
        status = 200
        headers = []
        for raw in head.split(b"\n"):
            line = raw.decode("latin1").strip()
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key.lower() == "status":
                status = int(value.split()[0])
            elif key and key.lower() not in ("content-length", "transfer-encoding"):
                headers.append((key, value))
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _backend
    do_POST = _backend

    def log_message(self, fmt, *args):
        print("[git-test-server]", args[0] if args else fmt, flush=True)


def main():
    handler = functools.partial(Handler)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), handler)
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"git-test-server (smart HTTP, TLS) on 0.0.0.0:{PORT} serving {REPOS}", flush=True)
    else:
        print(f"git-test-server (smart HTTP) on 0.0.0.0:{PORT} serving {REPOS}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
