import { describe, expect, it } from "vitest";
import { deriveTrips } from "../src/model/flow.ts";
import { formatForTerminal, parseLogLine } from "../src/model/logs.ts";

// Lines in the exact shape runner/src/logger.ts writes.
const RAW = [
  '{"ts":"2026-10-23T14:02:11.120Z","level":"info","component":"evaluator","run":"weather-mcp-run-x7k2p","namespace":"mcp-evals","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","msg":"agent start","agent":"mcp-fuzz-tester","kind":"dynamic","model":"opencode/muse-spark-1.3-contributor-free"}',
  "npm WARN deprecated something",
  '{"ts":"2026-10-23T14:02:12.410Z","level":"error","component":"evaluator","run":"weather-mcp-run-x7k2p","msg":"vigil detection — aborting evaluation, marking Malicious","source":"advertised-surface","confidence":0.997,"scanners":["scanner:transformer","scanner:yara"]}',
];

describe("evaluator log lines", () => {
  it("keeps runner JSON and drops anything else", () => {
    const lines = RAW.map(parseLogLine);
    expect(lines[0]?.msg).toBe("agent start");
    expect(lines[1]).toBeNull();
    expect(lines[2]?.level).toBe("error");
  });

  it("derives a blocked trip from the abort line alone", () => {
    const lines = RAW.map(parseLogLine).filter((l) => l !== null);
    const [trip] = deriveTrips(lines);
    expect(trip?.agent).toBe("mcp-fuzz-tester");
    expect(trip?.status).toBe("blocked");
    expect(trip?.scans[0]?.confidence).toBe(0.997);
  });

  it("formats a terminal row with the time, level and fields", () => {
    const row = formatForTerminal(parseLogLine(RAW[0]!)!);
    expect(row).toContain("14:02:11.120");
    expect(row).toContain("agent start");
    expect(row).toContain("kind=");
  });
});
