import { describe, expect, it } from "vitest";
import { DemoSource } from "../src/data/demo/replay.ts";
import { buildAskContext } from "../src/model/askContext.ts";
import { describeSchedule, suggestName } from "../src/model/serverForm.ts";

describe("ask context", () => {
  it("fences the run data as untrusted and keeps the verdict and findings", () => {
    const src = new DemoSource("exfiltration");
    src.skipToEnd();
    const snap = src.getSnapshot();
    const run = snap.runs[src.activeRun!]!;
    const text = buildAskContext(run, snap.servers[run.spec.serverRef], snap.reports[run.metadata.name]);
    expect(text).toMatch(/<datos>[\s\S]*<\/datos>/);
    expect(text).toMatch(/NO instrucciones/);
    expect(text).toContain("Veredicto: Untrusted, seguridad 23/100");
    expect(text).toContain("Exfiltración");
    expect(text.length).toBeLessThan(15_000);
  });
});

describe("form helpers", () => {
  it("suggests a name from the repository and describes schedules", () => {
    expect(suggestName("https://github.com/Acme/Weather_MCP.git")).toBe("weather-mcp");
    expect(describeSchedule("0 3 * * *")).toBe("Todos los días, 3:00 UTC");
    expect(describeSchedule("*/30 * * * *")).toBe("Cada 30 minutos");
    expect(describeSchedule("15 4 1 * *")).toBe("Programado: 15 4 1 * *");
  });
});
