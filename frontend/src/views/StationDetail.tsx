import type { ReactNode } from "react";
import { RiskTag, SeverityTag } from "../components/Tags.tsx";
import { ROLE_LABEL, seconds } from "../components/format.ts";
import type { Snapshot } from "../data/source.ts";
import type { RunData } from "../data/useRun.ts";
import { STATIONS, type StationId, type StationState, type Trip, type VigilScan } from "../model/flow.ts";
import { bySeverity } from "../model/crd.ts";
import { SCANNERS } from "../components/scanners.ts";

interface Props {
  station: StationId;
  state: StationState;
  trip: Trip;
  trips: Trip[];
  snap: Snapshot;
  data: RunData;
}

const SOURCE_LABEL: Record<string, string> = {
  "advertised-surface": "Superficie anunciada: descripciones y esquemas de tools, prompts y resources",
  "fuzz-responses": "Respuestas del servidor a los casos de fuzzing",
  "probe-responses": "Respuestas del servidor a las sondas adversariales",
};

const SCAN_WORD: Record<VigilScan["status"], string> = {
  pass: "Sin coincidencias",
  warn: "Un solo escáner: advertencia",
  block: "Dos escáneres coinciden: bloqueo",
  unavailable: "Vigil no respondió",
};

function Latency({ trip, station, state }: { trip: Trip; station: StationId; state: StationState }) {
  const ms = trip.extras?.latencyMs?.[station];
  if (ms === undefined || state === "idle" || state === "active" || state === "off") return null;
  return (
    <div className="fact">
      <dt>Latencia</dt>
      <dd>{seconds(ms)}</dd>
    </div>
  );
}

function scannerScore(scan: VigilScan, id: string): string {
  const hit = scan.warningRecords?.flatMap((w) => w.hits).find((h) => h.scanner === id);
  if (hit?.detail) return hit.detail;
  if (hit?.score !== undefined) return id === "scanner:vectordb" ? `distancia ${hit.score.toFixed(2)}` : `score ${hit.score.toFixed(3)}`;
  if (scan.detection?.scanners.includes(id)) {
    if (id === "scanner:transformer" && scan.detection.confidence !== undefined) return `score ${scan.detection.confidence.toFixed(3)}`;
    return "coincide";
  }
  if (scan.scanners.includes(id)) return "coincide";
  return "";
}

function VigilDetail({ trip, data }: { trip: Trip; data: RunData }) {
  if (trip.scans.length === 0) {
    const why =
      trip.kind === "static"
        ? "Este agente lee el código fuente como evidencia estática; Vigil revisa lo que el servidor dice en tiempo de ejecución."
        : trip.kind === "synthesis"
          ? "La síntesis solo lee los informes de los otros agentes, que ya pasaron por Vigil."
          : "El escaneo empieza cuando el evaluator recibe la superficie del servidor.";
    return <p className="muted">{why}</p>;
  }
  const threshold = data.report?.securityGate.vigil.transformerThreshold ?? 0.98;
  return (
    <>
      <p className="detail-lead">
        Cada texto del servidor se manda solo, en trozos de 500 caracteres. Corta si DeBERTa (umbral {threshold}) y otro escáner coinciden;
        un escáner solo deja una advertencia.
      </p>
      <ul className="scans">
        {trip.scans.map((scan, i) => (
          <li key={i} className={`scan scan-${scan.status}`}>
            <p className="scan-head">
              <strong>{SOURCE_LABEL[scan.source] ?? scan.source}</strong>
              <span>
                {scan.units !== undefined && `${scan.units} textos, `}
                {SCAN_WORD[scan.status]}
              </span>
            </p>
            <table className="votes">
              <tbody>
                {SCANNERS.map((s) => {
                  const score = scannerScore(scan, s.id);
                  return (
                    <tr key={s.id} className={score ? "vote-hit" : ""}>
                      <th scope="row">{s.name}</th>
                      <td className="muted">{s.what}</td>
                      <td>{score || (scan.status === "unavailable" ? "" : "sin coincidencia")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {(scan.detection ?? scan.warningRecords?.[0]) && (
              <figure className="excerpt">
                <figcaption>
                  Texto del servidor, no confiable ({scan.detection?.segment ?? scan.warningRecords?.[0]?.segment})
                </figcaption>
                <blockquote>{scan.detection?.excerpt ?? scan.warningRecords?.[0]?.excerpt}</blockquote>
              </figure>
            )}
            {scan.status !== "pass" && !scan.detection && !scan.warningRecords?.length && (
              <p className="muted small">Los votos por escáner llegan con el reporte, cuando termina el run.</p>
            )}
          </li>
        ))}
      </ul>
    </>
  );
}

function OccludraDetail({ trip, snap }: { trip: Trip; snap: Snapshot }) {
  const reds = trip.extras?.redactions;
  if (reds) {
    const total = reds.reduce((n, r) => n + r.count, 0);
    return (
      <>
        <p className="detail-lead">
          {total === 0
            ? "El prompt no tenía datos personales ni credenciales: salió sin cambios."
            : `Antes de salir del cluster, Occludra reemplazó ${total} ${total === 1 ? "dato" : "datos"} por [REDACTED].`}
        </p>
        {total > 0 && (
          <table className="redactions">
            <thead>
              <tr>
                <th scope="col">Detector</th>
                <th scope="col">Cantidad</th>
                <th scope="col">Ejemplo enmascarado</th>
              </tr>
            </thead>
            <tbody>
              {reds.map((r) => (
                <tr key={r.detector}>
                  <td>
                    <code>{r.detector}</code>
                  </td>
                  <td className="num">{r.count}</td>
                  <td>
                    {r.examples?.map((e) => (
                      <code key={e} className="masked">
                        {e}
                      </code>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">Ejemplos de la demo. En el cluster, Occludra solo cuenta redacciones por detector y nunca guarda el contenido.</p>
      </>
    );
  }
  const g = snap.gateway;
  if (g && g.redactions.length > 0) {
    return (
      <>
        <p className="detail-lead">Redacciones de todo el gateway en {g.window}, según occludra_redactions_total:</p>
        <table className="redactions">
          <tbody>
            {g.redactions.map((r) => (
              <tr key={r.detector}>
                <td>
                  <code>{r.detector}</code>
                </td>
                <td className="num">{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </>
    );
  }
  return (
    <p className="muted">
      Occludra enmascara emails, tokens, IBAN, teléfonos y contraseñas en cada request. No registra el contenido; para ver conteos por detector,
      levantá el backend con PROM_URL.
    </p>
  );
}

export function StationDetail({ station, state, trip, trips, snap, data }: Props) {
  const info = STATIONS.find((s) => s.id === station)!;
  const run = data.run;
  const role = snap.agents[trip.agent]?.spec.role ?? "";
  const synthesis = trips.find((t) => t.kind === "synthesis");

  let body: ReactNode = null;
  switch (station) {
    case "source": {
      const ev = data.report?.staticEvidenceSummary;
      body = (
        <>
          <p className="detail-lead">
            {trip.kind === "static"
              ? "El código fuente clonado, leído como evidencia: archivos, dependencias, sinks peligrosos y registros de tools."
              : trip.kind === "synthesis"
                ? "Nada nuevo del servidor: la síntesis trabaja con los informes de los otros agentes."
                : "El servidor corre en el contenedor target, sin red ni credenciales. Solo habla por stdin y stdout con el evaluator."}
          </p>
          {trip.kind === "static" && ev && (
            <dl className="facts-inline">
              <div className="fact">
                <dt>Archivos</dt>
                <dd>{ev.fileCount}</dd>
              </div>
              <div className="fact">
                <dt>Dependencias</dt>
                <dd>{ev.dependencyCount}</dd>
              </div>
              <div className="fact">
                <dt>Sinks</dt>
                <dd>{ev.sinkCount}</dd>
              </div>
            </dl>
          )}
          {trip.scans.length > 0 && (
            <ul className="plain">
              {[...new Set(trip.scans.map((s) => s.source))].map((s) => (
                <li key={s}>{SOURCE_LABEL[s] ?? s}</li>
              ))}
            </ul>
          )}
        </>
      );
      break;
    }
    case "vigil":
      body = <VigilDetail trip={trip} data={data} />;
      break;
    case "prompt":
      body = (
        <>
          <p className="detail-lead">
            {state === "off"
              ? "No se armó: Vigil cortó antes."
              : "La evidencia entra al mensaje como datos. Los agentes corren sin herramientas, así que una instrucción escondida no puede hacer que actúen."}
          </p>
          {trip.extras?.promptBytes !== undefined && state !== "off" && (
            <dl className="facts-inline">
              <div className="fact">
                <dt>Tamaño</dt>
                <dd>{(trip.extras.promptBytes / 1024).toFixed(0)} KiB</dd>
              </div>
            </dl>
          )}
        </>
      );
      break;
    case "occludra":
      body = state === "off" ? <p className="muted">No hubo request: el flujo se cortó en Vigil.</p> : <OccludraDetail trip={trip} snap={snap} />;
      break;
    case "netbird":
      body = (
        <p className="detail-lead">
          {state === "off"
            ? "No hubo tráfico."
            : "El request sale por el proxy SOCKS5 del sidecar (127.0.0.1:1080) y viaja por WireGuard hasta Occludra y Vigil. La NetworkPolicy del run no permite otra salida."}
        </p>
      );
      break;
    case "llm":
      body = (
        <>
          <p className="detail-lead">
            {state === "off"
              ? "Ningún modelo recibió el contenido."
              : state === "active"
                ? "Esperando la respuesta del modelo."
                : state === "fail"
                  ? "El modelo no devolvió una respuesta válida."
                  : "El modelo respondió con el JSON que pide el esquema del agente."}
          </p>
          <dl className="facts-inline">
            {trip.model && (
              <div className="fact">
                <dt>Modelo</dt>
                <dd>
                  <code>{trip.model}</code>
                </dd>
              </div>
            )}
          </dl>
          {trip.error && <p className="error-text">{trip.error}</p>}
        </>
      );
      break;
    case "agent": {
      const result = run?.status?.agentResults?.[trip.agent];
      body = (
        <>
          <dl className="facts-inline">
            <div className="fact">
              <dt>Agente</dt>
              <dd>{trip.agent}</dd>
            </div>
            <div className="fact">
              <dt>Rol</dt>
              <dd>{ROLE_LABEL[role] ?? role}</dd>
            </div>
            {trip.durationMs !== undefined && (
              <div className="fact">
                <dt>Duración</dt>
                <dd>{seconds(trip.durationMs)}</dd>
              </div>
            )}
          </dl>
          {result !== undefined ? (
            <>
              <p className="muted small">Lo que escribió en status.agentResults:</p>
              <pre className="json">{JSON.stringify(result, null, 2)}</pre>
            </>
          ) : (
            <p className="muted">{state === "off" ? "No llegó a responder." : "Todavía sin resultado."}</p>
          )}
        </>
      );
      break;
    }
    case "synthesis":
      body = (
        <p className="detail-lead">
          {state === "off"
            ? "No hizo falta: el corte de Vigil ya define el veredicto."
            : synthesis?.status === "ok"
              ? `SynthesisScorer combinó ${trips.filter((t) => t.kind !== "synthesis" && t.status === "ok").length} informes en un puntaje y una lista de hallazgos.`
              : synthesis?.status === "failed"
                ? "La síntesis falló y el evaluator usó un puntaje conservador."
                : "Corre al final, con los informes de los otros tres agentes."}
        </p>
      );
      break;
    case "verdict": {
      const status = run?.status;
      const findings = [...(status?.findings ?? [])].sort(bySeverity).slice(0, 3);
      body = status?.scoring ? (
        <>
          <p className="verdict-line">
            <span className="big">{status.finalScore ?? 0}</span>
            <RiskTag risk={status.scoring.riskCategory} />
          </p>
          {status.scoring.summary && <p className="detail-lead">{status.scoring.summary}</p>}
          <ul className="plain">
            {findings.map((f, i) => (
              <li key={i}>
                <SeverityTag severity={f.severity} /> {f.title}
              </li>
            ))}
          </ul>
          <pre className="json">{`kubectl -n mcp-evals get mcprun ${run?.metadata.name}\nPHASE: ${status.phase}  SCORE: ${status.finalScore ?? 0}  RISK: ${status.scoring.riskCategory}`}</pre>
        </>
      ) : (
        <p className="muted">El veredicto aparece en el status del CR cuando termina el run.</p>
      );
      break;
    }
  }

  return (
    <article className={`detail detail-${state}`} aria-live="polite">
      <header className="detail-head">
        <h3>{info.name}</h3>
        <p className="muted">{info.role}</p>
      </header>
      <dl className="facts-inline">
        <Latency trip={trip} station={station} state={state} />
      </dl>
      {body}
    </article>
  );
}
