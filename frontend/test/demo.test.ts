import { describe, expect, it } from "vitest";
import { DemoSource } from "../src/data/demo/replay.ts";
import { SCENARIOS } from "../src/data/demo/scenarios.ts";
import { deriveTrips, stationStates } from "../src/model/flow.ts";

function finished(id: string) {
  const src = new DemoSource(id);
  src.skipToEnd();
  const snap = src.getSnapshot();
  const runName = src.activeRun!;
  const run = snap.runs[runName]!;
  const trips = deriveTrips(snap.logs[runName] ?? [], snap.reports[runName], snap.extras[runName]);
  return { snap, run, trips, server: snap.servers[run.spec.serverRef]! };
}

describe("demo scenarios", () => {
  it("every scenario ends in a terminal phase with a report", () => {
    for (const sc of SCENARIOS) {
      const { run, snap } = finished(sc.id);
      expect(["Completed", "Failed"]).toContain(run.status?.phase);
      expect(snap.reports[run.metadata.name]?.runName).toBe(run.metadata.name);
    }
  });

  it("approved: four agents pass and the server is Safe", () => {
    const { run, trips, server } = finished("approved");
    expect(run.status?.scoring?.riskCategory).toBe("Safe");
    expect(trips.map((t) => t.status)).toEqual(["ok", "ok", "ok", "ok"]);
    expect(server.status?.overallRiskStatus).toBe("Safe");
    expect(server.status?.lastFinalScore).toBe(88);
  });

  it("vigil: the flow is cut at Vigil and the CR says Malicious", () => {
    const { run, trips, server } = finished("vigil");
    expect(run.status?.phase).toBe("Failed");
    expect(run.status?.finalScore).toBe(0);
    expect(server.status?.overallRiskStatus).toBe("Malicious");
    const blocked = trips.find((t) => t.status === "blocked")!;
    expect(blocked.agent).toBe("mcp-fuzz-tester");
    expect(blocked.scans[0]?.detection?.scanners).toEqual(["scanner:transformer", "scanner:yara"]);
    const st = stationStates(blocked, trips, run);
    expect(st.vigil).toBe("block");
    expect(st.llm).toBe("off");
    expect(st.verdict).toBe("block");
  });

  it("degraded: one agent fails, the run still completes and says so", () => {
    const { run, trips } = finished("degraded");
    expect(run.status?.phase).toBe("Completed");
    expect(run.status?.message).toMatch(/^degraded: 1\/4 agent\(s\) failed \(mcp-fuzz-tester\)/);
    expect(trips.find((t) => t.agent === "mcp-fuzz-tester")?.status).toBe("failed");
    expect(trips.find((t) => t.kind === "synthesis")?.status).toBe("ok");
  });

  it("exfiltration: rejected with a corroborated finding and a Vigil warning", () => {
    const { run, trips } = finished("exfiltration");
    expect(run.status?.scoring?.riskCategory).toBe("Untrusted");
    const fuzz = trips.find((t) => t.agent === "mcp-fuzz-tester")!;
    expect(fuzz.scans[0]?.status).toBe("warn");
    expect(fuzz.scans[0]?.warningRecords?.[0]?.hits[0]?.scanner).toBe("scanner:vectordb");
  });

  it("a fresh replay starts Pending", () => {
    const src = new DemoSource("approved");
    const snap = src.getSnapshot();
    expect(snap.runs[src.activeRun!]?.status?.phase).toBe("Pending");
  });
});
