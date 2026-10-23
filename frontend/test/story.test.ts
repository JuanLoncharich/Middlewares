import { describe, expect, it } from "vitest";
import { DemoSource } from "../src/data/demo/replay.ts";
import { type Snapshot, emptySnapshot } from "../src/data/source.ts";
import type { MCPEvaluationRun } from "../src/model/crd.ts";
import { buildStory } from "../src/model/story.ts";

function story(id: string) {
  const src = new DemoSource(id);
  src.skipToEnd();
  return buildStory(src.getSnapshot(), src.activeRun)!;
}

const states = (s: ReturnType<typeof story>) => s.steps.map((x) => `${x.id}:${x.state}`);

describe("analysis story", () => {
  it("approved: six steps in the order they happen; one minor observation; Safe", () => {
    const s = story("approved");
    expect(states(s)).toEqual([
      "prepare:ok",
      "agent-mcp-sast-auditor:warn",
      "vigil:ok",
      "agent-mcp-fuzz-tester:ok",
      "agent-mcp-rogue-detector:ok",
      "agent-mcp-synthesizer:ok",
    ]);
    expect(s.verdict).toMatchObject({ state: "safe", safety: 88, reliability: 91 });
  });

  it("vigil: the block is its own step and later agents never ran", () => {
    const s = story("vigil");
    expect(states(s).slice(2)).toEqual([
      "vigil:bad",
      "agent-mcp-fuzz-tester:skipped",
      "agent-mcp-rogue-detector:skipped",
      "agent-mcp-synthesizer:skipped",
    ]);
    const vigil = s.steps.find((x) => x.id === "vigil")!;
    expect(vigil.evidence?.[0]?.text).toMatch(/id_rsa/);
    expect(vigil.findings).toHaveLength(1);
    // Robustness was never measured, so the seal does not claim 0.
    expect(s.verdict).toMatchObject({ state: "malicious", safety: 0, reliability: undefined });
  });

  it("exfiltration: the advertised surface is counted once and the probe shows evidence", () => {
    const s = story("exfiltration");
    const vigil = s.steps.find((x) => x.id === "vigil")!;
    expect(vigil.state).toBe("warn");
    expect(vigil.facts.find((f) => f.label === "textos revisados")?.value).toBe("11");
    const probe = s.steps.find((x) => x.id === "agent-mcp-rogue-detector")!;
    expect(probe.state).toBe("bad");
    expect(probe.conclusion).toMatch(/mandar datos afuera/);
    expect(probe.evidence?.[0]?.text).toMatch(/hooks\.collector-demo\.net/);
    expect(s.verdict.state).toBe("untrusted");
  });

  it("degraded: the failed agent says why and the rest still count", () => {
    const s = story("degraded");
    const fuzz = s.steps.find((x) => x.id === "agent-mcp-fuzz-tester")!;
    expect(fuzz.state).toBe("failed");
    expect(fuzz.conclusion).toMatch(/LLMTimeoutError/);
    expect(s.steps.find((x) => x.id === "agent-mcp-synthesizer")?.state).toBe("ok");
    expect(s.verdict.state).toBe("caution");
  });

  it("a fresh replay is in progress with nothing concluded yet", () => {
    const src = new DemoSource("approved");
    const s = buildStory(src.getSnapshot(), src.activeRun)!;
    expect(s.verdict.state).toBe("running");
    expect(s.steps[0]?.state).toBe("running");
    expect(s.steps.slice(1).every((x) => x.state === "pending")).toBe(true);
  });

  it("a run whose pod never started is a platform failure, not a verdict", () => {
    // The real k0s case: the Job was retried twice and gave up while Pending.
    const run: MCPEvaluationRun = {
      apiVersion: "security.eval.io/v1alpha1",
      kind: "MCPEvaluationRun",
      metadata: { name: "fs-run-1" },
      spec: { serverRef: "filesystem-mcp", agents: ["mcp-sast-auditor", "mcp-synthesizer"] },
      status: {
        phase: "Failed",
        retries: 2,
        message: "transient failure repeated after 2 retries, giving up: pod fs-run-1-job-x stuck Pending without starting",
      },
    };
    const snap: Snapshot = { ...emptySnapshot(), runs: { [run.metadata.name]: run } };
    const s = buildStory(snap, run.metadata.name)!;
    expect(states(s)).toEqual(["prepare:failed", "agent-mcp-sast-auditor:skipped", "agent-mcp-synthesizer:skipped"]);
    expect(s.steps[0]?.conclusion).toMatch(/no es un veredicto/);
    expect(s.verdict.state).toBe("error");
  });
});
