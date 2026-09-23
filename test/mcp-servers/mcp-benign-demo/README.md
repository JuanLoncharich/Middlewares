# mcp-benign-demo

Benign MCP stdio server used as the **control sample** for local end-to-end
tests of the evaluation platform (`test/run-local-e2e.sh`). Plain Node, zero
dependencies; `.mcp-launch.json` tells the platform's cloner how to launch it.

Expected verdict: run **Completed**, no Critical findings, riskCategory
Safe/Caution.

Contrast with `../mcp-evil-demo/` (the malicious sample).
