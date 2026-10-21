# Vigil YARA rules (ours)

Mounted into every Vigil pod as the ConfigMap `vigil-yara-rules`
(`manifests/vigil-deployment.yaml`, and `hack/gpu-node/manifests/vigil-gpu.yaml`
for the GPU Vigil), replacing the rules upstream bakes into the image at
`/app/data/yara`.

**Role:** a second opinion. A YARA match never aborts an evaluation on its
own. The run aborts only when Vigil's transformer AND a YARA rule (or the
vectordb) flag the same text (`runner/src/vigil.ts`, `combineScannerResults`).
A single scanner only warns.

| File | Rules |
|---|---|
| `injection.yar` | InstructionOverride, RoleHijack, SystemPromptExtraction, HiddenInstructionMarker, ChatTemplateMarker |
| `exfiltration.yar` | ExfiltrationInstruction, MarkdownImageExfiltration, CredentialInText |

## Upstream rules (vigil-llm @ f2b4c13)

| Upstream file | Kept? | Why |
|---|---|---|
| `instruction_bypass.yar` | Replaced by InstructionOverride | Case-sensitive (`Ignore`, not `IGNORE`), no filler words (misses "ignore **all** previous instructions"), yet matches bare "ignore input" / "skip data" in docs. |
| `system_instructions.yar`, `guidance.yar` | Kept, inside ChatTemplateMarker | Exact chat-template tokens; precise. |
| `mdexfil.yar` | Kept as MarkdownImageExfiltration | Specific exfiltration technique; precise. |
| `ssh.yar` | Kept inside CredentialInText | Private-key header; precise. |
| `apitokens.yar` | Partly, inside CredentialInText | Only distinctive token prefixes. Dropped the shapes that match ordinary identifiers and hashes: Artifactory `AP[0-9A-F]…`, Twilio `SK` + 32 hex, Mailchimp, Telegram, LinkedIn. |
| `generic_secret.yar` | Dropped | "secret key" / "access token" phrases are everywhere in benign docs. |
| `ip.yar` | Dropped | IP addresses are normal in infrastructure tools and docs. |
| `react.yar`, `react_txt.yar` | Dropped | "Thought:/Action:/Observation:" also appears in agent-framework docs and code; not an attack by itself. |

Tests and benchmark: `test/vigil/yara-rules-test.py`.
