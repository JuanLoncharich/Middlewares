import { useMemo } from "react";
import { PhaseTag, RiskTag, SeverityTag } from "../components/Tags.tsx";
import { PHASE_LABEL, relativeTime, shortRepo } from "../components/format.ts";
import { type MCPEvaluationRun, type MCPServer, RUN_PHASES, bySeverity, isTerminal, verdictOf } from "../model/crd.ts";
import type { Snapshot } from "../data/source.ts";

interface Row {
  server: MCPServer;
  run: MCPEvaluationRun | undefined;
  /** Last run that reached a verdict (the in-flight run has none yet). */
  verdictRun: MCPEvaluationRun | undefined;
}

type Column = "evaluating" | "approved" | "rejected" | "unknown";

function group(snap: Snapshot): Record<Column, Row[]> {
  const out: Record<Column, Row[]> = { evaluating: [], approved: [], rejected: [], unknown: [] };
  const runs = Object.values(snap.runs);
  for (const server of Object.values(snap.servers)) {
    const run = server.status?.lastRunRef ? snap.runs[server.status.lastRunRef] : undefined;
    const verdictRun = runs
      .filter((r) => r.spec.serverRef === server.metadata.name && r.status?.scoring)
      .sort((a, b) => (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""))[0];
    const row = { server, run, verdictRun };
    if (run && !isTerminal(run.status?.phase)) out.evaluating.push(row);
    else out[verdictOf(server.status?.overallRiskStatus)].push(row);
  }
  for (const col of Object.values(out)) col.sort((a, b) => a.server.metadata.name.localeCompare(b.server.metadata.name));
  return out;
}

const PROGRESS_STEPS = RUN_PHASES.slice(0, 5);

function Progress({ run }: { run: MCPEvaluationRun }) {
  const phase = run.status?.phase ?? "Pending";
  const at = PROGRESS_STEPS.indexOf(phase === "Failed" ? "Completed" : phase);
  const agents = run.spec.agents;
  const done = Object.keys(run.status?.agentResults ?? {}).length;
  return (
    <div className="progress">
      <ol className="progress-phases" aria-label="Fases">
        {PROGRESS_STEPS.slice(0, 4).map((p, i) => (
          <li key={p} className={i < at ? "done" : i === at ? "now" : ""}>
            {PHASE_LABEL[p]}
          </li>
        ))}
      </ol>
      {phase === "Evaluating" && (
        <p className="progress-agent">
          {run.status?.currentAgent} <span className="muted">(agente {Math.min(done + 1, agents.length)} de {agents.length})</span>
        </p>
      )}
    </div>
  );
}

function Ticket({ row, column, onOpen }: { row: Row; column: Column; onOpen: () => void }) {
  const { server, run, verdictRun } = row;
  const findings = [...(verdictRun?.status?.findings ?? [])].sort(bySeverity).slice(0, 2);
  return (
    <li>
      <button type="button" className={`ticket ticket-${column}`} onClick={onOpen}>
        <span className="ticket-head">
          <span className="ticket-name">{server.metadata.name}</span>
          {column !== "evaluating" && <span className="ticket-score">{server.status?.lastFinalScore ?? 0}</span>}
        </span>
        <span className="ticket-repo">{shortRepo(server.spec.repositoryUrl)}</span>
        {column === "evaluating" && run && <Progress run={run} />}
        {column !== "evaluating" && (
          <span className="ticket-meta">
            <RiskTag risk={server.status?.overallRiskStatus} />
            <span className="muted">{relativeTime(verdictRun?.status?.completionTime)}</span>
          </span>
        )}
        {column === "rejected" && findings.length > 0 && (
          <ul className="ticket-findings">
            {findings.map((f, i) => (
              <li key={i}>
                <SeverityTag severity={f.severity} /> {f.title}
              </li>
            ))}
          </ul>
        )}
        {column === "unknown" && run && <PhaseTag phase={run.status?.phase} />}
      </button>
    </li>
  );
}

const COLUMNS: { id: Column; title: string; empty: string }[] = [
  { id: "evaluating", title: "En evaluación", empty: "Nada en el sandbox ahora mismo." },
  { id: "approved", title: "Aprobados", empty: "Todavía ningún servidor salió Seguro o Precaución." },
  { id: "rejected", title: "Rechazados", empty: "Ningún servidor rechazado." },
];

export function ServersView({ snap, onOpen }: { snap: Snapshot; onOpen: (server: string) => void }) {
  const groups = useMemo(() => group(snap), [snap]);
  const total = Object.keys(snap.servers).length;
  if (total === 0) {
    return (
      <section className="view empty-state">
        <h2>Sin servidores MCP</h2>
        <p>
          No hay recursos <code>MCPServer</code> en el namespace. Creá uno con <code>kubectl apply -k config/samples</code> o cambiá a modo
          demo.
        </p>
      </section>
    );
  }
  return (
    <section className="view servers" aria-label="Servidores MCP">
      {COLUMNS.map((col) => (
        <div key={col.id} className={`column column-${col.id}`}>
          <h2>
            {col.title} <span className="count">{groups[col.id].length}</span>
          </h2>
          {groups[col.id].length === 0 ? (
            <p className="muted">{col.empty}</p>
          ) : (
            <ul className="tickets">
              {groups[col.id].map((row) => (
                <Ticket key={row.server.metadata.name} row={row} column={col.id} onOpen={() => onOpen(row.server.metadata.name)} />
              ))}
            </ul>
          )}
        </div>
      ))}
      {groups.unknown.length > 0 && (
        <div className="column column-unknown">
          <h2>
            Sin veredicto <span className="count">{groups.unknown.length}</span>
          </h2>
          <ul className="tickets">
            {groups.unknown.map((row) => (
              <Ticket key={row.server.metadata.name} row={row} column="unknown" onOpen={() => onOpen(row.server.metadata.name)} />
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
