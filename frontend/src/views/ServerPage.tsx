import { useEffect, useMemo, useRef, useState } from "react";
import { AskPanel } from "../components/AskPanel.tsx";
import { Findings, Seal, StepList } from "../components/RunStory.tsx";
import { relativeTime, shortRepo } from "../components/format.ts";
import type { Theme } from "../components/theme.ts";
import { actions } from "../data/actions.ts";
import type { DataSource, Mode, Snapshot } from "../data/source.ts";
import { type MCPEvaluationRun, isTerminal } from "../model/crd.ts";
import { describeSchedule, isGitManaged } from "../model/serverForm.ts";
import { buildStory } from "../model/story.ts";
import { RISK_KIND, serverState } from "../model/verdict.ts";
import { go, href } from "../router.ts";
import { TerminalView } from "./TerminalView.tsx";

interface Props {
  snap: Snapshot;
  source: DataSource;
  mode: Mode;
  theme: Theme;
  name: string;
  runName: string | null;
}

export function ServerPage({ snap, source, mode, theme, name, runName }: Props) {
  const server = snap.servers[name];
  const state = server ? serverState(snap, server) : null;
  const run = (runName ? snap.runs[runName] : undefined) ?? state?.running ?? state?.latest;
  const story = useMemo(() => buildStory(snap, run?.metadata.name ?? null), [snap, run?.metadata.name]);
  const [tab, setTab] = useState<"story" | "log">("story");
  const [message, setMessage] = useState<{ text: string; error?: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const confirm = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    source.follow(run?.metadata.name ?? null);
  }, [source, run?.metadata.name]);

  if (!server || !state) {
    return (
      <div className="page">
        <a className="back" href={href({ page: "servers" })}>
          Servidores
        </a>
        <div className="empty panel">
          <h1>No existe el servidor {name}</h1>
          <p>Puede que lo hayan borrado. Volvé a la lista para ver los que hay.</p>
        </div>
      </div>
    );
  }

  const git = isGitManaged(server);
  const paused = server.spec.active === false;
  const live = mode === "live";
  const act = async (what: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    setMessage(null);
    try {
      await what();
      setMessage({ text: ok });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : String(err), error: true });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    confirm.current?.close();
    setBusy(true);
    try {
      await actions.remove(name);
      go({ page: "servers" });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : String(err), error: true });
      setBusy(false);
    }
  };
  const lockReason = !live ? "Disponible en modo Live" : git ? "Se gestiona desde git: cambialo ahí" : undefined;

  return (
    <div className="page">
      <a className="back" href={href({ page: "servers" })}>
        Servidores
      </a>

      <header className="server-head">
        <div className="server-id">
          <h1>{server.metadata.name}</h1>
          <p className="muted">
            <a href={server.spec.repositoryUrl} target="_blank" rel="noreferrer noopener">
              {shortRepo(server.spec.repositoryUrl)}
            </a>
            {server.spec.path ? ` / ${server.spec.path}` : ""}, rama {server.spec.ref ?? "main"}.{" "}
            {paused ? "Evaluaciones pausadas." : `${describeSchedule(server.spec.schedule)}.`}
            {git && <span className="tag">desde git</span>}
          </p>
        </div>
        <div className="server-actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!live || busy || !!state.running || paused}
            title={!live ? "Disponible en modo Live" : paused ? "Reanudalo para evaluarlo" : undefined}
            onClick={() => void act(() => actions.evaluate(name), "Pedido enviado: la evaluación empieza en unos segundos.")}
          >
            {state.running ? "Evaluando…" : "Evaluar ahora"}
          </button>
          <button
            type="button"
            className="btn"
            disabled={!!lockReason || busy}
            title={lockReason}
            onClick={() =>
              void act(
                () => actions.setPaused(name, !paused),
                paused ? "Reanudado: vuelve a evaluarse con su frecuencia." : "Pausado: no se evalúa hasta que lo reanudes.",
              )
            }
          >
            {paused ? "Reanudar" : "Pausar"}
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={!!lockReason || busy}
            title={lockReason}
            onClick={() => confirm.current?.showModal()}
          >
            Borrar
          </button>
        </div>
      </header>
      {message && (
        <p className={`notice ${message.error ? "notice-error" : "notice-ok"}`} role="status">
          {message.text}
        </p>
      )}

      {!story ? (
        <div className="empty panel">
          <h2>Todavía no se evaluó</h2>
          <p>{paused ? "Está pausado. Reanudalo para que se evalúe." : "La primera evaluación arranca en unos segundos."}</p>
        </div>
      ) : (
        <>
          <section className="verdict-hero panel" aria-label="Veredicto">
            <Seal verdict={story.verdict} progress={`${story.steps.filter((s) => s.state !== "pending" && s.state !== "running").length} de ${story.steps.length} pasos`} />
            <div className="verdict-text">
              <p className="verdict-q">¿Es seguro conectarlo a un agente de IA?</p>
              <p className="verdict-a">{story.verdict.answer}</p>
              <RunHistory runs={state.runs} current={run?.metadata.name} server={name} now={snap.now ?? Date.now()} />
            </div>
          </section>

          <div className="tabs" role="tablist" aria-label="Vista del análisis">
            <button type="button" role="tab" aria-selected={tab === "story"} className="tab" onClick={() => setTab("story")}>
              Qué pasó
            </button>
            <button type="button" role="tab" aria-selected={tab === "log"} className="tab" onClick={() => setTab("log")}>
              Registro técnico
            </button>
          </div>

          <div className="server-body">
            <div className="server-main">
              {tab === "story" ? (
                <>
                  <StepList steps={story.steps} snap={snap} />
                  <Findings findings={story.findings} snap={snap} />
                </>
              ) : (
                <TerminalView snap={snap} runName={run?.metadata.name ?? null} mode={mode} theme={theme} />
              )}
            </div>
            <aside className="server-side">
              <AskPanel key={run!.metadata.name} run={run!.metadata.name} mode={mode} finished={isTerminal(run?.status?.phase)} />
            </aside>
          </div>
        </>
      )}

      <dialog ref={confirm} className="confirm" aria-labelledby="confirm-title">
        <h2 id="confirm-title">¿Borrar {name}?</h2>
        <p>Se borran el servidor y todas sus evaluaciones. No se puede deshacer.</p>
        <div className="confirm-actions">
          <button type="button" className="btn" onClick={() => confirm.current?.close()}>
            Cancelar
          </button>
          <button type="button" className="btn btn-danger-solid" onClick={() => void remove()}>
            Borrar servidor
          </button>
        </div>
      </dialog>
    </div>
  );
}

function RunHistory({ runs, current, server, now }: { runs: MCPEvaluationRun[]; current?: string; server: string; now: number }) {
  if (runs.length < 2) return null;
  return (
    <nav className="history" aria-label="Evaluaciones anteriores">
      <span className="muted">Evaluaciones:</span>
      <ol>
        {runs.slice(0, 6).map((r) => {
          const risk = r.status?.scoring?.riskCategory;
          const kind = !isTerminal(r.status?.phase) ? "running" : risk && risk !== "Unknown" ? RISK_KIND[risk].kind : "error";
          const when = relativeTime(r.metadata.creationTimestamp, now);
          return (
            <li key={r.metadata.name}>
              <a
                className={`history-dot v-${kind}`}
                href={href({ page: "server", server, run: r.metadata.name })}
                aria-current={r.metadata.name === current ? "true" : undefined}
                title={when}
              >
                <span className="sr-only">{when}</span>
              </a>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
