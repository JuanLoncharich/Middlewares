import { RiskTag } from "../components/Tags.tsx";
import { PHASE_LABEL, ROLE_LABEL, clock, seconds } from "../components/format.ts";
import type { Snapshot } from "../data/source.ts";
import { useNow, usePhaseTimes, useRun } from "../data/useRun.ts";
import { type RunPhase, isTerminal } from "../model/crd.ts";
import type { Trip } from "../model/flow.ts";

const PHASE_NOTES: Record<RunPhase, string> = {
  Pending: "El operador aceptó el CR y crea el Job.",
  Cloning: "Init container: clona el repo e instala dependencias. Única fase con salida a git y a los registros.",
  Running: "Arrancan target y evaluator. La red se cierra: solo DNS, API server y NetBird.",
  Evaluating: "Los cuatro agentes corren uno detrás de otro.",
  Completed: "Puntaje y hallazgos escritos en el status.",
  Failed: "El run terminó sin completar la evaluación.",
};

const MAIN_PHASES: RunPhase[] = ["Pending", "Cloning", "Running", "Evaluating"];

type LaneStatus = "pending" | "running" | "ok" | "failed" | "blocked" | "skipped";

const LANE_LABEL: Record<LaneStatus, string> = {
  pending: "En espera",
  running: "Corriendo",
  ok: "Terminó",
  failed: "Falló",
  blocked: "Cortado por Vigil",
  skipped: "No corrió",
};

export function LifecycleView({ snap, runName }: { snap: Snapshot; runName: string | null }) {
  const { run, report, trips } = useRun(snap, runName);
  const phase = run?.status?.phase ?? "Pending";
  const terminal = isTerminal(phase);
  const now = useNow(snap.now, !terminal);
  const times = usePhaseTimes(run, now);

  if (!run) {
    return (
      <section className="view empty-state">
        <h2>Elegí un run</h2>
        <p>Usá el selector de arriba para ver las fases y los agentes de una evaluación.</p>
      </section>
    );
  }

  const status = run.status ?? {};
  const message = status.message ?? "";
  const degraded = message.startsWith("degraded:");
  const vigilCut = phase === "Failed" && status.scoring?.riskCategory === "Malicious";
  const end = terminal ? Date.parse(status.completionTime ?? new Date(now).toISOString()) : now;
  const start = Date.parse(status.startTime ?? run.metadata.creationTimestamp ?? new Date(now).toISOString());
  const span = Math.max(end - start, 1);
  const reached = MAIN_PHASES.indexOf(phase);

  const lanes = run.spec.agents.map((name) => {
    const trip: Trip | undefined = trips.find((t) => t.agent === name);
    const rec = report?.agents[name];
    let state: LaneStatus;
    if (trip) state = trip.status === "running" && terminal ? "skipped" : trip.status;
    else if (status.agentResults?.[name] !== undefined) state = "ok";
    else if (rec) state = rec.status;
    else state = terminal ? "skipped" : "pending";
    const role = snap.agents[name]?.spec.role ?? rec?.role ?? "";
    const from = trip ? Date.parse(trip.startedAt) : undefined;
    const to = trip?.endedAt ? Date.parse(trip.endedAt) : state === "running" ? now : undefined;
    const duration = trip?.durationMs ?? rec?.durationMs ?? (from !== undefined && to !== undefined ? to - from : undefined);
    return { name, role, state, from, to, duration, error: trip?.error ?? rec?.error, current: status.currentAgent === name };
  });
  const failed = lanes.filter((l) => l.state === "failed");

  return (
    <section className="view lifecycle" aria-label="Ciclo de vida del run">
      <header className="run-head">
        <div>
          <h2>{run.spec.serverRef}</h2>
          <p className="muted">
            <code>{run.metadata.name}</code>
            {status.retries ? `, reintentado ${status.retries} ${status.retries === 1 ? "vez" : "veces"}` : ""}
          </p>
        </div>
        {status.scoring && (
          <div className="run-verdict">
            <span className="big">{status.finalScore ?? 0}</span>
            <RiskTag risk={status.scoring.riskCategory} />
          </div>
        )}
      </header>

      <ol className="phases">
        {MAIN_PHASES.map((p, i) => {
          const state = terminal || i < reached ? "done" : i === reached ? "now" : "todo";
          return (
            <li key={p} className={`phase phase-${state}`} aria-current={state === "now" ? "step" : undefined}>
              <span className="phase-num">{i + 1}</span>
              <span className="phase-name">{PHASE_LABEL[p]}</span>
              <span className="phase-time">{times[p] ? clock(times[p]) : ""}</span>
              <span className="phase-note">{PHASE_NOTES[p]}</span>
            </li>
          );
        })}
        <li className={`phase phase-end ${terminal ? `phase-${phase.toLowerCase()}` : "phase-todo"}`}>
          <span className="phase-num">5</span>
          <span className="phase-name">{terminal ? PHASE_LABEL[phase] : "Completado o fallido"}</span>
          <span className="phase-time">{terminal ? clock(status.completionTime) : ""}</span>
          <span className="phase-note">{terminal ? PHASE_NOTES[phase] : "Lo decide el evaluator al terminar."}</span>
        </li>
      </ol>

      {degraded && (
        <p className="banner banner-warn" role="status">
          Run degradado: {failed.length} de {lanes.length} agentes {failed.length === 1 ? "falló" : "fallaron"} y el resto siguió. El puntaje es más conservador.
          <span className="banner-raw">{message}</span>
        </p>
      )}
      {vigilCut && (
        <p className="banner banner-block" role="status">
          Vigil cortó la evaluación: el contenido del servidor intentó manipular a los agentes. Ningún modelo llegó a verlo.
        </p>
      )}
      {phase === "Failed" && !vigilCut && message && (
        <p className="banner banner-block" role="status">
          {message}
        </p>
      )}

      <div className="lanes" role="table" aria-label="Agentes">
        <div className="lane lane-head" role="row">
          <span role="columnheader">Agente</span>
          <span role="columnheader">Estado</span>
          <span role="columnheader">Tiempo desde el inicio del run</span>
        </div>
        {lanes.map((l) => {
          const left = l.from !== undefined ? ((l.from - start) / span) * 100 : 0;
          const width = l.from !== undefined && l.to !== undefined ? Math.max(((l.to - l.from) / span) * 100, 0.8) : 0;
          return (
            <div key={l.name} className={`lane lane-${l.state} ${l.current ? "lane-current" : ""}`} role="row">
              <span role="cell" className="lane-who">
                <strong>{ROLE_LABEL[l.role] ?? l.role}</strong>
                <span className="muted small">{l.name}</span>
              </span>
              <span role="cell" className="lane-state">
                <span className="lane-dot" aria-hidden="true" />
                {LANE_LABEL[l.state]}
                {l.duration !== undefined && l.state !== "pending" && <span className="muted"> {seconds(l.duration)}</span>}
              </span>
              <span role="cell" className="lane-track">
                {width > 0 && <span className="lane-bar" style={{ left: `${left}%`, width: `${Math.min(width, 100 - left)}%` }} />}
                {l.error && <span className="lane-error">{l.error}</span>}
              </span>
            </div>
          );
        })}
      </div>

      {!terminal && message && <p className="muted small run-message">Último mensaje del evaluator: {message}</p>}
    </section>
  );
}

