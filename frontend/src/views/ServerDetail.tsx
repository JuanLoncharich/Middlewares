import { useEffect, useRef } from "react";
import { PhaseTag, RiskTag, SeverityTag } from "../components/Tags.tsx";
import { ROLE_LABEL, clock, relativeTime, shortRepo } from "../components/format.ts";
import { bySeverity } from "../model/crd.ts";
import { type Snapshot, runsOf } from "../data/source.ts";

interface Props {
  snap: Snapshot;
  name: string;
  onClose: () => void;
  onShowRun: (run: string) => void;
}

export function ServerDetail({ snap, name, onClose, onShowRun }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
  }, []);

  const server = snap.servers[name];
  if (!server) return null;
  const runs = runsOf(snap, name);
  const verdictRun = runs.find((r) => r.status?.scoring);
  const scoring = verdictRun?.status?.scoring;
  const findings = [...(verdictRun?.status?.findings ?? [])].sort(bySeverity);
  const spec = server.spec;

  return (
    <dialog ref={ref} className="drawer" aria-labelledby="drawer-title" onClose={onClose} onCancel={onClose}>
      <header className="drawer-head">
        <div>
          <h2 id="drawer-title">{name}</h2>
          <a href={spec.repositoryUrl.replace(/\.git$/, "")} target="_blank" rel="noreferrer">
            {shortRepo(spec.repositoryUrl)}
          </a>
        </div>
        <button type="button" className="button-quiet" onClick={onClose}>
          Cerrar
        </button>
      </header>

      <dl className="facts">
        <div>
          <dt>Ref</dt>
          <dd>
            <code>{spec.ref ?? "main"}</code>
            {spec.path && (
              <>
                {" "}
                en <code>{spec.path}</code>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Transporte</dt>
          <dd>{spec.transport === "sse" ? `SSE en el puerto ${spec.targetPort ?? 8080}` : "stdio"}</dd>
        </div>
        <div>
          <dt>Agenda</dt>
          <dd>
            <code>{spec.schedule}</code>
            {spec.active === false && " (pausada)"}
          </dd>
        </div>
        <div>
          <dt>Agentes</dt>
          <dd>
            {spec.agentSuite
              .map((a) => ROLE_LABEL[snap.agents[a.name]?.spec.role ?? ""] ?? a.name)
              .join(", ")}
          </dd>
        </div>
      </dl>

      <section className="drawer-section">
        <h3>Veredicto</h3>
        {scoring ? (
          <div className="verdict-block">
            <p className="verdict-score">
              <span className="big">{verdictRun?.status?.finalScore ?? scoring.safetyScore}</span>
              <span className="muted">de 100 en seguridad, {scoring.reliabilityScore} en robustez</span>
            </p>
            <RiskTag risk={scoring.riskCategory} />
            {scoring.summary && <p>{scoring.summary}</p>}
            {verdictRun?.status?.message?.startsWith("degraded") && <p className="note-warn">{verdictRun.status.message}</p>}
          </div>
        ) : (
          <p className="muted">Todavía no hay un run con veredicto.</p>
        )}
      </section>

      {findings.length > 0 && (
        <section className="drawer-section">
          <h3>Hallazgos</h3>
          <ul className="findings">
            {findings.map((f, i) => (
              <li key={i}>
                <p className="finding-title">
                  <SeverityTag severity={f.severity} /> {f.title}
                </p>
                {f.description && <p className="finding-desc">{f.description}</p>}
                {f.remediation && <p className="finding-fix">Qué hacer: {f.remediation}</p>}
                <p className="muted small">Lo reportó {f.agent}</p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="drawer-section">
        <h3>Historial de runs</h3>
        <table className="history">
          <thead>
            <tr>
              <th scope="col">Run</th>
              <th scope="col">Inicio</th>
              <th scope="col">Fase</th>
              <th scope="col">Puntaje</th>
              <th scope="col">Riesgo</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.metadata.name}>
                <td>
                  <button type="button" className="link" onClick={() => onShowRun(r.metadata.name)}>
                    {r.metadata.name}
                  </button>
                </td>
                <td title={r.metadata.creationTimestamp}>
                  {clock(r.metadata.creationTimestamp)} <span className="muted">{relativeTime(r.metadata.creationTimestamp)}</span>
                </td>
                <td>
                  <PhaseTag phase={r.status?.phase} />
                </td>
                <td className="num">{r.status?.scoring ? r.status.finalScore ?? 0 : ""}</td>
                <td>{r.status?.scoring && <RiskTag risk={r.status.scoring.riskCategory} />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </dialog>
  );
}
