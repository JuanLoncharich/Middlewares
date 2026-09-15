# mcp-eval-runner

Evaluator container for `MCPEvaluationRun` pods. Boots an OpenCode server per
`OpenCodeAgent` (via `@opencode-ai/sdk/v2`), collects static / dynamic /
adversarial evidence against the target MCP server, requests structured
JSON output per agent and patches `MCPEvaluationRun.status` through
`@kubernetes/client-node`.

## Environment contract

| Variable | Default | Purpose |
|---|---|---|
| `RUN_NAME` | — | `MCPEvaluationRun` name (status patch target) |
| `RUN_NAMESPACE` | — | namespace of the run (downward API) |
| `SERVER_NAME` | — | `MCPServer` name to evaluate |
| `AGENT_NAMES` | — | comma-separated `OpenCodeAgent` names, in execution order |
| `TRANSPORT` | `stdio` | `stdio` (FIFOs in `IPC_DIR`) or `sse` (`127.0.0.1:TARGET_PORT`) |
| `TARGET_PORT` | `8080` | port for the SSE transport |
| `WORKSPACE_DIR` | `/workspace` | read-only clone of the target repository |
| `IPC_DIR` | `/ipc` | `stdin`/`stdout` FIFOs, `crashes.jsonl`, `target.log`, `done` sentinel |
| `OUTPUT_DIR` | `/output` | `evaluation-report.json` destination |
| `OPENCODE_PORT` | `4096` | loopback port for the per-agent OpenCode server |
| `ANTHROPIC_API_KEY` | — | consumed by OpenCode's Anthropic provider |
| `DRY_RUN` | unset | `1` = no API server: agents from `OUTPUT_DIR/agents/*.json`, server from `OUTPUT_DIR/server.json`, patches logged |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` (JSON logs on stderr) |

Exit code `0` = `Completed`, `1` = `Failed`. A JSON termination message
`{phase, finalScore, riskCategory, message}` is written to
`/dev/termination-log` for the operator.

## Local dry run

```bash
npm ci && npm run build
mkdir -p /tmp/out/agents
kubectl -n mcp-evals get opencodeagent -o json | jq -c '.items[]' | \
  while read -r a; do echo "$a" > "/tmp/out/agents/$(echo "$a" | jq -r .metadata.name).json"; done
kubectl -n mcp-evals get mcpserver filesystem-mcp -o json > /tmp/out/server.json
DRY_RUN=1 OUTPUT_DIR=/tmp/out WORKSPACE_DIR=$PWD/../some-clone IPC_DIR=/tmp/ipc \
  AGENT_NAMES=mcp-sast-auditor,mcp-synthesizer ANTHROPIC_API_KEY=... node dist/evaluator.js
```
