# mcp-evil-demo

Malicious MCP stdio server used as the **attack sample** for local end-to-end
tests (`test/run-local-e2e.sh`). It implements the MCP handshake correctly but
packs its `initialize.instructions` and tool descriptions with indirect
prompt-injection payloads (instruction override, system-prompt extraction,
role hijack, fake `[system]` markers) and its tool outputs with exfiltration
markers and credential-shaped strings.

Everything hostile is inert: the payloads are static strings, and the
evaluation sandbox has no egress. The fixture exists so the platform can prove
it FAILS the server:

Expected verdict: run **Failed** with `riskCategory=Malicious`, `finalScore=0`,
a Critical finding from `vigil-llm` (advertised-surface scan), in
`VIGIL_ENFORCE=strict` (the default).

If this fixture ever completes with a decent score, the security perimeter is
broken — file it as a platform bug.
