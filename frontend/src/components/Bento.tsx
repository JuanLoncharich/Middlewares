import type { ReactNode } from "react";
import { type MCPEvaluationRun, type MCPServer, isTerminal, verdictOf } from "../model/crd.ts";
import { RISK_LABEL } from "../model/report.ts";
import { PhaseTag } from "./Tags.tsx";
import { PHASE_LABEL, shortRepo } from "./format.ts";

type Span = 3 | 4 | 5 | 6 | 7 | 8 | 9 | 12;

interface TileProps {
  span: Span;
  rows?: 2 | 3;
  title?: string;
  tone?: "plain" | "evaluating" | "approved" | "rejected" | "warn";
  className?: string;
  label?: string;
  children: ReactNode;
}

/** One cell of a bento grid. Size carries the hierarchy, not decoration. */
export function Tile({ span, rows, title, tone = "plain", className = "", label, children }: TileProps) {
  return (
    <section
      className={`tile span-${span} ${rows ? `rows-${rows}` : ""} tile-${tone} ${className}`}
      aria-label={label ?? title}
    >
      {title && <h3 className="tile-title">{title}</h3>}
      {children}
    </section>
  );
}

export function Stat({ value, label, note }: { value: ReactNode; label: string; note?: string }) {
  return (
    <div className="stat">
      <p className="stat-value">{value}</p>
      <p className="stat-label">{label}</p>
      {note && <p className="stat-note">{note}</p>}
    </div>
  );
}

/** The run's name, its repository and the latest word from the evaluator. */
export function RunHeadTile({
  run,
  server,
  span = 8,
  aside,
}: {
  run: MCPEvaluationRun;
  server?: MCPServer;
  span?: Span;
  aside?: ReactNode;
}) {
  const status = run.status ?? {};
  const summary = status.scoring?.summary ?? (isTerminal(status.phase) ? status.message : undefined);
  return (
    <Tile span={span} className="tile-head" label="Run seleccionado">
      <h2 className="head-server">{run.spec.serverRef}</h2>
      {server && (
        <p className="head-repo">
          {shortRepo(server.spec.repositoryUrl)} en <code>{server.spec.ref ?? "main"}</code>, transporte {server.spec.transport ?? "stdio"}
        </p>
      )}
      <p className="head-run">
        <code>{run.metadata.name}</code> <PhaseTag phase={status.phase} />
      </p>
      {aside}
      {summary && <p className="head-summary">{summary}</p>}
    </Tile>
  );
}

/** The verdict as one solid tile: the colour is the answer. */
export function VerdictTile({ run, span = 4 }: { run: MCPEvaluationRun; span?: Span }) {
  const status = run.status ?? {};
  const scoring = status.scoring;
  const phase = status.phase ?? "Pending";
  if (!scoring || !isTerminal(phase)) {
    const total = run.spec.agents.length;
    const done = Object.keys(status.agentResults ?? {}).length;
    return (
      <Tile span={span} tone="evaluating" className="tile-verdict" title="Veredicto">
        <p className="verdict-big">
          {done}
          <span className="verdict-of">/{total}</span>
        </p>
        <p className="verdict-word">{PHASE_LABEL[phase]}</p>
        <p className="verdict-note">
          {phase === "Evaluating" ? "agentes con resultado; el puntaje llega al final." : "El sandbox se está preparando."}
        </p>
      </Tile>
    );
  }
  const v = verdictOf(scoring.riskCategory);
  return (
    <Tile
      span={span}
      tone={v === "rejected" ? "rejected" : scoring.riskCategory === "Caution" ? "warn" : "approved"}
      className="tile-verdict"
      title="Veredicto"
    >
      <p className="verdict-big">{status.finalScore ?? scoring.safetyScore}</p>
      <p className="verdict-word">{RISK_LABEL[scoring.riskCategory]}</p>
      <p className="verdict-note">
        {scoring.safetyScore} en seguridad, {scoring.reliabilityScore} en robustez
      </p>
    </Tile>
  );
}
