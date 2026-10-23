// Demo data source: replays scenario timelines against a virtual clock and
// produces the same objects the live backend would (CRs, log lines, reports).
import { API_VERSION, type MCPEvaluationRun, isTerminal } from "../../model/crd.ts";
import type { LogLine } from "../../model/logs.ts";
import { type DataSource, type ReplayState, type Snapshot, emptySnapshot, mergeRunStatus } from "../source.ts";
import { BACKGROUND, DEMO_AGENTS, SCENARIOS } from "./scenarios.ts";
import type { Scenario, Step } from "./script.ts";

const TICK_MS = 100;
/** The background run moves at half the replay speed so it outlasts a scenario. */
const BACKGROUND_RATE = 0.5;
/** It starts mid-evaluation, so the board never opens empty. */
const BACKGROUND_OFFSET_MS = 18_000;
const BACKGROUND_PAUSE_MS = 12_000;
const HOUR = 3_600_000;

interface Playback {
  scenario: Scenario;
  runName: string;
  startWall: number;
  traceId: string;
  elapsed: number;
  cursor: number;
}

function hex(n: number): string {
  let out = "";
  for (let i = 0; i < n; i++) out += Math.floor(Math.random() * 16).toString(16);
  return out;
}

function suffix(): string {
  const chars = "bcdfghjklmnpqrstvwxz2456789";
  let out = "";
  for (let i = 0; i < 5; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

export class DemoSource implements DataSource {
  readonly mode = "demo" as const;
  private snap: Snapshot = emptySnapshot();
  private readonly listeners = new Set<() => void>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private active: Playback | null = null;
  private bg: Playback | null = null;
  private bgIdleMs = 0;
  private replay: ReplayState;
  private readonly replayListeners = new Set<() => void>();

  constructor(scenarioId = SCENARIOS[0]!.id) {
    this.replay = { scenario: scenarioId, playing: true, speed: 1, elapsedMs: 0, durationMs: 0 };
    this.reset();
  }

  // --- DataSource ------------------------------------------------------------

  getSnapshot = (): Snapshot => this.snap;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick(), TICK_MS);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  follow(): void {
    // Every demo run already carries its log.
  }

  // --- replay controls -------------------------------------------------------

  getReplay = (): ReplayState => this.replay;

  subscribeReplay = (listener: () => void): (() => void) => {
    this.replayListeners.add(listener);
    return () => this.replayListeners.delete(listener);
  };

  /** Name of the run the replay is driving; the UI selects it. */
  get activeRun(): string | null {
    return this.active?.runName ?? null;
  }

  setPlaying(playing: boolean): void {
    this.setReplay({ playing });
  }

  setSpeed(speed: number): void {
    this.setReplay({ speed });
  }

  setScenario(id: string): void {
    this.replay = { ...this.replay, scenario: id };
    this.reset();
  }

  restart(): void {
    this.reset();
  }

  /** Jumps the scenario to its verdict. */
  skipToEnd(): void {
    if (!this.active) return;
    this.active.elapsed = this.active.scenario.durationMs;
    this.advance(this.active);
    this.emit();
    this.setReplay({ elapsedMs: this.active.elapsed });
  }

  // --- internals -------------------------------------------------------------

  private setReplay(patch: Partial<ReplayState>): void {
    this.replay = { ...this.replay, ...patch };
    for (const l of this.replayListeners) l();
  }

  private reset(): void {
    const now = Date.now();
    const snap = emptySnapshot();
    for (const a of DEMO_AGENTS) snap.agents[a.metadata.name] = a;
    this.snap = snap;

    // History: each server already has finished runs from earlier days.
    const all = [...SCENARIOS, BACKGROUND];
    all.forEach((sc, i) => {
      for (const daysAgo of [2, 1]) {
        const pb = this.newPlayback(sc, now - daysAgo * 24 * HOUR - (i + 1) * HOUR);
        pb.elapsed = sc.durationMs;
        this.advance(pb);
      }
    });

    const scenario = SCENARIOS.find((s) => s.id === this.replay.scenario) ?? SCENARIOS[0]!;
    this.active = this.newPlayback(scenario, now);
    this.bg = this.newPlayback(BACKGROUND, now - BACKGROUND_OFFSET_MS);
    this.bg.elapsed = BACKGROUND_OFFSET_MS;
    this.bgIdleMs = 0;
    this.advance(this.bg);
    this.advance(this.active);
    this.emit();
    this.setReplay({ elapsedMs: 0, durationMs: scenario.durationMs, playing: true });
  }

  private newPlayback(scenario: Scenario, startWall: number): Playback {
    const runName = `${scenario.server.metadata.name}-run-${suffix()}`;
    const created = new Date(startWall).toISOString();
    const serverName = scenario.server.metadata.name;
    const prevServer = this.snap.servers[serverName] ?? scenario.server;
    const run: MCPEvaluationRun = {
      apiVersion: API_VERSION,
      kind: "MCPEvaluationRun",
      metadata: {
        name: runName,
        namespace: "mcp-evals",
        creationTimestamp: created,
        labels: { "security.eval.io/server": serverName },
      },
      spec: {
        serverRef: serverName,
        agents: scenario.server.spec.agentSuite.map((a) => a.name),
        timeoutSeconds: scenario.server.spec.timeoutSeconds ?? 900,
      },
      status: { phase: "Pending", startTime: created },
    };
    this.snap = {
      ...this.snap,
      runs: { ...this.snap.runs, [runName]: run },
      servers: {
        ...this.snap.servers,
        [serverName]: {
          ...prevServer,
          status: { ...prevServer.status, lastRunRef: runName, lastEvaluationDate: created },
        },
      },
      logs: { ...this.snap.logs, [runName]: [] },
    };
    return { scenario, runName, startWall, traceId: hex(32), elapsed: 0, cursor: 0 };
  }

  private tick(): void {
    if (!this.replay.playing) return;
    const delta = TICK_MS * this.replay.speed;
    let changed = false;

    if (this.active) {
      this.active.elapsed = Math.min(this.active.elapsed + delta, this.active.scenario.durationMs);
      changed = this.advance(this.active) || changed;
      if (this.active.elapsed !== this.replay.elapsedMs) this.setReplay({ elapsedMs: this.active.elapsed });
    }

    if (this.bg) {
      if (this.bg.cursor < this.bg.scenario.steps.length) {
        this.bg.elapsed += delta * BACKGROUND_RATE;
        changed = this.advance(this.bg) || changed;
      } else if ((this.bgIdleMs += delta) > BACKGROUND_PAUSE_MS) {
        // The cron fires again: a fresh background run.
        this.bg = this.newPlayback(BACKGROUND, Date.now());
        this.bgIdleMs = 0;
        changed = true;
      }
    }

    if (changed) this.emit();
  }

  /** Applies every step due at the playback's elapsed time; true if any applied. */
  private advance(pb: Playback): boolean {
    const steps = pb.scenario.steps;
    let applied = false;
    while (pb.cursor < steps.length && steps[pb.cursor]!.at <= pb.elapsed) {
      this.apply(pb, steps[pb.cursor]!);
      pb.cursor += 1;
      applied = true;
    }
    return applied;
  }

  private apply(pb: Playback, step: Step): void {
    const ts = new Date(pb.startWall + step.at).toISOString();
    const runName = pb.runName;
    switch (step.kind) {
      case "status": {
        const prev = this.snap.runs[runName];
        if (!prev) return;
        const patch = { ...step.patch };
        if (patch.phase === "Cloning") patch.jobName = runName;
        if (isTerminal(patch.phase)) patch.completionTime = ts;
        const run: MCPEvaluationRun = { ...prev, status: mergeRunStatus(prev.status, patch) };
        this.snap = { ...this.snap, runs: { ...this.snap.runs, [runName]: run } };
        if (isTerminal(patch.phase)) this.recordVerdict(run);
        break;
      }
      case "log": {
        const fields = { ...step.fields };
        if (typeof fields["configmap"] === "string") fields["configmap"] = fields["configmap"].replace("<run>", runName);
        const line: LogLine = {
          ts,
          level: step.level,
          component: step.component,
          run: runName,
          namespace: "mcp-evals",
          trace_id: pb.traceId,
          span_id: hex(16),
          msg: step.msg,
          ...fields,
        };
        const prev = this.snap.logs[runName] ?? [];
        this.snap = { ...this.snap, logs: { ...this.snap.logs, [runName]: [...prev, line] } };
        break;
      }
      case "extras": {
        const prev = this.snap.extras[runName] ?? {};
        this.snap = { ...this.snap, extras: { ...this.snap.extras, [runName]: { ...prev, [step.agent]: step.data } } };
        break;
      }
      case "report": {
        const startedAt = new Date(pb.startWall).toISOString();
        const report = pb.scenario.report(runName, startedAt, ts);
        this.snap = { ...this.snap, reports: { ...this.snap.reports, [runName]: report } };
        break;
      }
    }
  }

  /** What the MCPServer controller writes when a run ends (mcpserver_controller.go). */
  private recordVerdict(run: MCPEvaluationRun): void {
    const name = run.spec.serverRef;
    const server = this.snap.servers[name];
    if (!server || server.status?.lastRunRef !== run.metadata.name) return;
    const risk = run.status?.scoring?.riskCategory;
    const verdict =
      run.status?.phase === "Completed" || risk === "Malicious"
        ? { overallRiskStatus: risk ?? "Unknown", lastFinalScore: run.status?.finalScore ?? 0 }
        : { overallRiskStatus: "Unknown" };
    this.snap = {
      ...this.snap,
      servers: { ...this.snap.servers, [name]: { ...server, status: { ...server.status, ...verdict } } },
    };
  }

  private emit(): void {
    for (const l of this.listeners) l();
  }
}
