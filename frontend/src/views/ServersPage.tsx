import { relativeTime, shortRepo } from "../components/format.ts";
import type { Snapshot } from "../data/source.ts";
import type { MCPServer } from "../model/crd.ts";
import { describeSchedule, isGitManaged } from "../model/serverForm.ts";
import { type ServerState, serverState } from "../model/verdict.ts";
import { href } from "../router.ts";

interface Props {
  snap: Snapshot;
  onNew: () => void;
}

export function ServersPage({ snap, onNew }: Props) {
  const now = snap.now ?? Date.now();
  const rows = Object.values(snap.servers)
    .map((s) => ({ server: s, state: serverState(snap, s) }))
    .sort((a, b) => order(a.state) - order(b.state) || a.server.metadata.name.localeCompare(b.server.metadata.name));
  const count = (kinds: string[]) => rows.filter((r) => kinds.includes(r.state.kind)).length;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Servidores MCP</h1>
          <p className="page-lede">
            Antes de conectar un servidor MCP a un agente de IA, la plataforma lo arranca en una caja aislada, lo revisa y
            dice si es seguro. Cada servidor se vuelve a evaluar solo, con la frecuencia que elijas.
          </p>
        </div>
        <button type="button" className="btn btn-primary" onClick={onNew}>
          Evaluar un servidor
        </button>
      </header>

      {rows.length > 0 && (
        <dl className="tally" aria-label="Resumen">
          <div>
            <dt>Evaluando ahora</dt>
            <dd>{count(["running"])}</dd>
          </div>
          <div>
            <dt>Seguros</dt>
            <dd className="t-safe">{count(["safe"])}</dd>
          </div>
          <div>
            <dt>Para revisar</dt>
            <dd className="t-caution">{count(["caution"])}</dd>
          </div>
          <div>
            <dt>Rechazados</dt>
            <dd className="t-bad">{count(["untrusted", "malicious"])}</dd>
          </div>
        </dl>
      )}

      {rows.length === 0 ? (
        <div className="empty panel">
          <h2>Todavía no hay servidores</h2>
          <p>Pegá el repositorio de un servidor MCP y la plataforma lo evalúa. Tarda unos minutos.</p>
          <button type="button" className="btn btn-primary" onClick={onNew}>
            Evaluar un servidor
          </button>
        </div>
      ) : (
        <table className="servers panel">
          <thead>
            <tr>
              <th scope="col">Servidor</th>
              <th scope="col">Veredicto</th>
              <th scope="col">Última evaluación</th>
              <th scope="col">Frecuencia</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ server, state }) => (
              <Row key={server.metadata.name} server={server} state={state} now={now} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Row({ server, state, now }: { server: MCPServer; state: ServerState; now: number }) {
  const link = href({ page: "server", server: server.metadata.name, run: null });
  const when = state.running
    ? "Ahora"
    : relativeTime(state.latest?.status?.completionTime ?? server.status?.lastEvaluationDate, now) || "Nunca";
  return (
    <tr>
      <th scope="row">
        <a className="row-link" href={link}>
          {server.metadata.name}
        </a>
        <span className="row-sub">
          {shortRepo(server.spec.repositoryUrl)}
          {server.spec.path ? `/${server.spec.path}` : ""}
        </span>
        {isGitManaged(server) && <span className="tag">desde git</span>}
      </th>
      <td>
        <VerdictBadge state={state} />
      </td>
      <td>{when}</td>
      <td className="muted">{server.spec.active === false ? "Pausado" : describeSchedule(server.spec.schedule)}</td>
    </tr>
  );
}

export function VerdictBadge({ state }: { state: ServerState }) {
  return (
    <span className={`verdict v-${state.kind}`}>
      {state.label}
      {state.score !== undefined && state.kind !== "running" ? <span className="verdict-score">{state.score}</span> : null}
    </span>
  );
}

function order(s: ServerState): number {
  return ["running", "malicious", "untrusted", "caution", "error", "none", "safe", "paused"].indexOf(s.kind);
}
