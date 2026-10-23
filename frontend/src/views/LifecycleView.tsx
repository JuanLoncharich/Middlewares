import { RunHeadTile, Stat, Tile, VerdictTile } from "../components/Bento.tsx";
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
  const { run, server, report, trips } = useRun(snap, runName);
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

  const okCount = lanes.filter((l) => l.state === "ok").length;
  const elapsed = Math.max(end - start, 0);

  return (
    <div className="bento view" aria-label="Ciclo de vida del run">
      <RunHeadTile run={run} server={server} />
      <VerdictTile run={run} />

      <Tile span={4} className="tile-stat">
        <Stat value={seconds(elapsed)} label={terminal ? "duró el run" : "lleva el run"} />
      </Tile>
      <Tile span={4} className="tile-stat" tone={failed.length > 0 ? "warn" : "plain"}>
        <Stat value={`${okCount} de ${lanes.length}`} label="agentes terminaron bien" note={failed.length > 0 ? `${failed.length} ${failed.length === 1 ? "falló" : "fallaron"}` : undefined} />
      </Tile>
      <Tile span={4} className="tile-stat">
        <Stat
          value={status.retries ?? 0}
          label={status.retries === 1 ? "reintento del Job" : "reintentos del Job"}
          note="Solo por fallas de infraestructura, máximo 2."
        />
      </Tile>

      <Tile span={12} title="Fases">
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
      </Tile>

      {degraded && (
        <Tile span={12} tone="warn" className="tile-banner" label="Run degradado">
          <p className="banner-lead" role="status">
            Run degradado: {failed.length} de {lanes.length} agentes {failed.length === 1 ? "falló" : "fallaron"} y el resto siguió. El puntaje es más
            conservador.
          </p>
          <p className="banner-raw">{message}</p>
        </Tile>
      )}
      {vigilCut && (
        <Tile span={12} tone="rejected" className="tile-banner" label="Corte de Vigil">
          <p className="banner-lead" role="status">
            Vigil cortó la evaluación: el contenido del servidor intentó manipular a los agentes. Ningún modelo llegó a verlo.
          </p>
        </Tile>
      )}
      {phase === "Failed" && !vigilCut && message && (
        <Tile span={12} tone="rejected" className="tile-banner" label="Run fallido">
          <p className="banner-lead" role="status">
            {message}
          </p>
        </Tile>
      )}

      <Tile span={12} title="Agentes">
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
      </Tile>
    </div>
  );
}

