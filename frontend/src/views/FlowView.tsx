import { Fragment, useEffect, useState } from "react";
import { RunHeadTile, Stat, Tile, VerdictTile } from "../components/Bento.tsx";
import { ROLE_LABEL } from "../components/format.ts";
import { SCANNERS } from "../components/scanners.ts";
import type { Snapshot } from "../data/source.ts";
import { useRun } from "../data/useRun.ts";
import { STATIONS, type StationId, type StationState, type Trip, type VigilScan, stationStates } from "../model/flow.ts";
import { RISK_LABEL } from "../model/report.ts";
import { StationDetail } from "./StationDetail.tsx";
import "../styles/flow.css";

const STATE_WORD: Record<StationState, string> = {
  idle: "en espera",
  active: "en curso",
  pass: "pasó",
  warn: "pasó con advertencia",
  block: "bloqueó",
  fail: "falló",
  off: "no participa",
};

type Lamp = "off" | "idle" | "pass" | "warn" | "block";

/** One lamp per Vigil scanner for the selected trip. */
export function lamps(trip: Trip, vigil: StationState): Record<string, Lamp> {
  const out: Record<string, Lamp> = {};
  for (const s of SCANNERS) {
    if (vigil === "off") out[s.id] = "off";
    else if (vigil === "idle" || vigil === "active") out[s.id] = "idle";
    else out[s.id] = "pass";
  }
  for (const scan of trip.scans) {
    if (scan.status === "pass") continue;
    const hit = scannersOf(scan);
    for (const id of hit) {
      const level: Lamp = scan.status === "block" ? "block" : "warn";
      if (out[id] !== "block") out[id] = level;
    }
  }
  return out;
}

function scannersOf(scan: VigilScan): string[] {
  if (scan.detection) return scan.detection.scanners;
  if (scan.scanners.length > 0) return scan.scanners;
  return [...new Set((scan.warningRecords ?? []).flatMap((w) => w.scanners))];
}

const VERDICT_WORD: Partial<Record<StationState, string>> = {
  pass: "aprobado",
  warn: "aprobado con reservas",
  block: "rechazado",
  fail: "fallido",
};

const TRIP_WORD: Record<Trip["status"], string> = {
  running: "en curso",
  ok: "terminó",
  failed: "falló",
  blocked: "cortado por Vigil",
};

function defaultStation(states: Record<StationId, StationState>): StationId {
  if (states.vigil === "block") return "vigil";
  const active = STATIONS.find((s) => states[s.id] === "active");
  if (active) return active.id;
  const failed = STATIONS.find((s) => states[s.id] === "fail");
  return failed?.id ?? "verdict";
}

export function FlowView({ snap, runName }: { snap: Snapshot; runName: string | null }) {
  const data = useRun(snap, runName);
  const { run, trips } = data;
  const [pinnedTrip, setPinnedTrip] = useState<number | null>(null);
  const [pinnedStation, setPinnedStation] = useState<StationId | null>(null);

  useEffect(() => {
    setPinnedTrip(null);
    setPinnedStation(null);
  }, [runName]);

  // Follow the newest trip unless the presenter picked one.
  const tripIndex = pinnedTrip !== null && pinnedTrip < trips.length ? pinnedTrip : trips.length - 1;
  const trip = trips[tripIndex];

  if (!run) {
    return (
      <section className="view empty-state">
        <h2>Elegí un run</h2>
        <p>El flujo se arma con los eventos del evaluator del run seleccionado.</p>
      </section>
    );
  }

  const phase = run.status?.phase ?? "Pending";
  if (!trip) {
    return (
      <div className="bento view" aria-label="Flujo del prompt">
        <RunHeadTile run={run} server={data.server} />
        <VerdictTile run={run} />
        <Tile span={12} className="tile-hero" title="Recorrido del prompt">
          <p className="flow-waiting-title">Todavía no salió ningún prompt.</p>
          <p className="muted">
            {phase === "Pending" || phase === "Cloning" || phase === "Running"
              ? "El sandbox se está preparando: el primer agente arranca cuando el evaluator está listo."
              : "Este run no tiene eventos del evaluator. En live, los logs del pod duran 10 minutos después de terminar el Job."}
          </p>
        </Tile>
      </div>
    );
  }

  const states = stationStates(trip, trips, run);
  const station = pinnedStation ?? defaultStation(states);
  const lit = lamps(trip, states.vigil);
  const blocked = states.vigil === "block";

  const scanned = trips.reduce((n, t) => n + t.scans.reduce((m, sc) => m + (sc.units ?? 0), 0), 0);
  const warnings = trips.reduce((n, t) => n + t.scans.filter((sc) => sc.status === "warn").length, 0);
  const redacted = trips.some((t) => t.extras?.redactions)
    ? trips.reduce((n, t) => n + (t.extras?.redactions ?? []).reduce((m, r) => m + r.count, 0), 0)
    : snap.gateway
      ? snap.gateway.redactions.reduce((m, r) => m + r.count, 0)
      : null;

  return (
    <div className="bento view" aria-label="Flujo del prompt">
      <RunHeadTile
        run={run}
        server={data.server}
        aside={run.status?.currentAgent ? <p className="flow-now">Ahora: {run.status.currentAgent}</p> : undefined}
      />
      <VerdictTile run={run} />

      <Tile span={12} className={`tile-hero ${blocked ? "tile-hero-cut" : ""}`} title="Recorrido del prompt">
        <ol className="trips" aria-label="Llamadas al modelo de este run">
          {trips.map((t, i) => (
            <li key={t.id}>
              <button
                type="button"
                className={`trip trip-${t.status} ${i === tripIndex ? "trip-on" : ""}`}
                aria-pressed={i === tripIndex}
                onClick={() => {
                  setPinnedTrip(i === trips.length - 1 ? null : i);
                  setPinnedStation(null);
                }}
              >
                <span className="trip-num">{i + 1}</span>
                <span className="trip-name">{ROLE_LABEL[snap.agents[t.agent]?.spec.role ?? ""] ?? t.agent}</span>
                <span className="trip-state">{TRIP_WORD[t.status]}</span>
              </button>
            </li>
          ))}
          {pinnedTrip !== null && (
            <li>
              <button type="button" className="button-quiet" onClick={() => setPinnedTrip(null)}>
                Seguir la última
              </button>
            </li>
          )}
        </ol>

        <div className={`pipeline ${blocked ? "pipeline-cut" : ""}`} role="list" aria-label="Estaciones">
          {STATIONS.map((s, i) => {
            const st = states[s.id];
            const next = STATIONS[i + 1];
            const nextSt = next ? states[next.id] : undefined;
            let seg = "seg-idle";
            if (next) {
              if (s.id === "vigil" && blocked) seg = "seg-cut";
              else if (st === "off" || nextSt === "off") seg = "seg-off";
              else if (nextSt === "active") seg = "seg-moving";
              else if (nextSt && nextSt !== "idle" && st !== "idle" && st !== "active") seg = `seg-done seg-${nextSt}`;
            }
            return (
              <Fragment key={s.id}>
                <div role="listitem" className={`station-wrap ${s.id === "vigil" ? "station-wrap-vigil" : ""}`}>
                  <button
                    type="button"
                    className={`station station-${st} ${station === s.id ? "station-on" : ""}`}
                    aria-pressed={station === s.id}
                    aria-label={`${s.name}: ${STATE_WORD[st]}`}
                    onClick={() => setPinnedStation(s.id)}
                  >
                    <span className="station-num">{i + 1}</span>
                    <span className="station-name">{s.name}</span>
                    {s.id === "vigil" ? (
                      <span className="lamps">
                        {SCANNERS.map((sc) => (
                          <span key={sc.id} className={`lamp lamp-${lit[sc.id]}`}>
                            <span className="lamp-bulb" aria-hidden="true" />
                            {sc.name}
                          </span>
                        ))}
                      </span>
                    ) : (
                      <span className="station-role">{s.role}</span>
                    )}
                    {s.id === "verdict" && run.status?.scoring && st !== "idle" && (
                      <span className="station-verdict">
                        {run.status.finalScore ?? 0} <small>{RISK_LABEL[run.status.scoring.riskCategory]}</small>
                      </span>
                    )}
                    <span className="station-state">{(s.id === "verdict" && VERDICT_WORD[st]) || STATE_WORD[st]}</span>
                  </button>
                  {st === "active" && <span className="packet packet-here" aria-hidden="true" />}
                </div>
                {next && (
                  <div className={`seg ${seg}`} aria-hidden="true">
                    {seg === "seg-moving" && <span className="packet packet-moving" />}
                    {seg === "seg-cut" && <span className="cut-label">Cortado</span>}
                  </div>
                )}
              </Fragment>
            );
          })}
        </div>

        {blocked && (
          <p className="cut-banner" role="status">
            Vigil detectó una inyección en el texto del servidor. El prompt nunca se armó, ningún modelo lo vio y el run quedó{" "}
            <strong>Malicioso con puntaje 0</strong>.
          </p>
        )}
      </Tile>

      <Tile span={8} tone={states[station] === "block" ? "rejected" : "plain"} className="tile-detail" label="Detalle de la estación">
        <StationDetail station={station} state={states[station]} trip={trip} trips={trips} snap={snap} data={data} />
      </Tile>

      <Tile span={4} title="En este run" className="tile-stats">
        <Stat value={trips.length} label={trips.length === 1 ? "llamada al modelo" : "llamadas al modelo"} />
        <Stat value={scanned} label="textos revisados por Vigil" note={warnings > 0 ? `${warnings} con advertencia` : undefined} />
        <Stat
          value={redacted ?? "sin dato"}
          label="datos enmascarados por Occludra"
          note={redacted === null ? "En live hace falta PROM_URL." : undefined}
        />
      </Tile>
    </div>
  );
}
