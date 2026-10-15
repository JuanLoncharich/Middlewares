# Chroma (namespace `chroma`)

The vector database behind Vigil's `vectordb` scanner. Architecture and
component table: `ARCHITECTURE.md` §5.2.1. This page covers how it is
deployed, secured and tested.

```
 security-gateways                 chroma
 ┌──────────────┐  Bearer reader  ┌────────────────┐        ┌────────────────────────┐
 │ vigil (CPU)  │ ──────────────▶ │ chroma-gateway │ ─────▶ │ rust-frontend-service  │──▶ sysdb, log, query, MinIO…
 │ vigil-gpu    │      :8080      │ nginx          │  :8000 │ (or chroma-single)     │
 └──────────────┘                 └────────────────┘        └────────────────────────┘
                                         ▲ Bearer writer
                                  vigil-corpus-loader (Job)
```

## Why a gateway

Chroma's Rust server, distributed frontend and single-node alike, has **no
authentication** (checked in the 1.5.x binary: no auth provider settings).
Anyone who reaches port 8000 can read, overwrite or delete the corpus, and
poisoning the corpus blinds Vigil. So:

- `chroma-gateway` (nginx, `gateway.yaml`) is the only pod reachable from
  outside the namespace (NetworkPolicies in `networkpolicy.yaml`), and only
  from the Vigil pods.
- It accepts two tokens:
  - **reader** (Vigil): `GET …/collections/<name>` and
    `POST …/collections/<id>/query` only, the two calls
    `images/vigil-llm/remote_vectordb.py` makes. Anything else answers 403.
    The path is matched on the raw URI with a strict per-segment charset, so
    `..`, `%2F` or `//` cannot turn an allowed path into another one.
  - **writer** (loader): everything.
- No or unknown token answers 401. `/api/v2/heartbeat` is open for probes.
- The gateway strips the `Authorization` header before proxying and refuses
  to start if a token is shorter than 32 characters or both are equal.

This is defense in depth. The NetworkPolicy already limits who can connect,
and the token also covers paths the policy cannot see: a Vigil pod
offloaded to another cluster (Liqo), a mistaken policy, or a compromised pod
in an allowed namespace. A stolen reader token can read the corpus but never
change it.

## Tokens

`hack/chroma/deploy.sh` creates them on first run (64 hex chars each from
Python's `secrets`). They travel only through pipes, never through argv,
files or output.

| Secret | Namespace | Keys | Used by |
|---|---|---|---|
| `chroma-auth` | `chroma` | `reader-token`, `writer-token` | gateway, loader Job |
| `chroma-reader` | `security-gateways` | `token` (copy of the reader token) | Vigil CPU and GPU, as env `CHROMA_TOKEN` |

The writer token never leaves namespace `chroma`. Without `chroma-reader`,
the Vigil pods do not start (`CreateContainerConfigError`); this is
deliberate, so they fail visibly instead of answering 401 on every scan.

Rotate both tokens with `CHROMA_ROTATE_TOKENS=1 hack/chroma/deploy.sh`.
The script restarts the gateway and the Vigil Deployments, because pods read
the tokens at start.

## Deploy

`deploy.sh` runs `hack/chroma/deploy.sh` when `DEPLOY_VECTOR_DB=1` (the
default). The script also runs on its own:

```bash
# local kind test cluster: one Chroma pod (emptyDir), same gateway and policies
CONTEXT=kind-mcp-e2e VECTOR_DB_MODE=single hack/chroma/deploy.sh

# the university k0s cluster: distributed, sized for 2 workers of 3.9 GB
CONTEXT=k0s CHROMA_QUERY_REPLICAS=1 CHROMA_COMPACTION_REPLICAS=1 hack/chroma/deploy.sh
```

The loader Job runs on stock `python:alpine`, pinned by digest, with
`images/vigil-corpus-loader/load_corpus.py` mounted from a ConfigMap. There
is no image to build or push, so any cluster that can pull from Docker Hub
can load the corpus.

## Tests

| Test | What it proves | Where |
|---|---|---|
| `test/chroma/gateway-test.sh` | 22 checks: 401/403/200 per token and path, encoded and dot-dot paths refused, start-up guards, tokens absent from logs | Docker, real Chroma |
| `test/vigil/remote-vectordb-test.sh` | Vigil's client through the gateway: queries with the reader token, fails closed with no or a wrong token without leaking it, and the reader token cannot write | Docker |
| `test/vigil/patches-test.sh <image>` | the Vigil image end to end against Chroma (fail closed, auto-update off) | Docker |
| `test/kind/chroma-access-test.sh` | live NetworkPolicies and tokens from pods carrying the real clients' labels (13 checks) | any cluster (`CONTEXT=…`) |

## Limits

- The single-node mode keeps its data in an emptyDir. A pod restart empties
  it; re-run the script (or only the loader).
- Token comparison in nginx is not constant-time. At 64 random hex chars over
  the cluster network, timing attacks are not a practical concern here.
- MinIO and Postgres still use the chart's fixed in-namespace credentials.
  Only pods in `chroma` can reach them (NetworkPolicy).
