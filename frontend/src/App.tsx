import { useEffect, useMemo, useState } from "react";
import { Logo } from "./components/Logo.tsx";
import { ReplayBar } from "./components/ReplayBar.tsx";
import { type Theme, applyTheme, initialTheme } from "./components/theme.ts";
import { DemoSource } from "./data/demo/replay.ts";
import { useReplay, useSnapshot } from "./data/hooks.ts";
import { LiveSource } from "./data/live.ts";
import type { Mode, Snapshot } from "./data/source.ts";
import { type MCPEvaluationRun, isTerminal } from "./model/crd.ts";
import { AnalysisView } from "./views/AnalysisView.tsx";
import { ServerDetail } from "./views/ServerDetail.tsx";
import { TerminalView } from "./views/TerminalView.tsx";
import { ServersView } from "./views/ServersView.tsx";
import "./styles/app.css";
import "./styles/bento.css";
import "./styles/analysis.css";
import "./styles/chrome.css";

type ViewId = "analysis" | "servers" | "terminal";

const VIEWS: { id: ViewId; label: string; key: string }[] = [
  { id: "analysis", label: "Análisis", key: "1" },
  { id: "servers", label: "Servidores", key: "2" },
  { id: "terminal", label: "Registro técnico", key: "3" },
];

function initialMode(): Mode {
  return new URLSearchParams(location.search).get("mode") === "live" ? "live" : "demo";
}

/** In live mode, follow the newest in-flight run, else the newest run. */
function pickLiveRun(snap: Snapshot): string | null {
  const runs = Object.values(snap.runs).sort((a, b) =>
    (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""),
  );
  return (runs.find((r) => !isTerminal(r.status?.phase)) ?? runs[0])?.metadata.name ?? null;
}

function runLabel(r: MCPEvaluationRun): string {
  const at = r.metadata.creationTimestamp ? new Date(r.metadata.creationTimestamp) : null;
  const when = at ? at.toLocaleString("es-AR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
  return `${r.spec.serverRef}${when ? `, ${when}` : ""}`;
}

export function App() {
  const demo = useMemo(() => new DemoSource(), []);
  const live = useMemo(() => new LiveSource(), []);
  const [mode, setMode] = useState<Mode>(initialMode);
  const source = mode === "demo" ? demo : live;
  const snap = useSnapshot(source);
  const replay = useReplay(mode === "demo" ? demo : null);
  const [view, setView] = useState<ViewId>("analysis");
  const [selectedRun, setSelectedRun] = useState<string | null>(null);
  const [openServer, setOpenServer] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [termOpened, setTermOpened] = useState(false);
  useEffect(() => {
    if (view === "terminal") setTermOpened(true);
  }, [view]);

  useEffect(() => applyTheme(theme), [theme]);

  useEffect(() => {
    source.start();
    return () => source.stop();
  }, [source]);

  // Demo: the selection follows the scenario being replayed.
  const activeDemoRun = mode === "demo" ? demo.activeRun : null;
  useEffect(() => {
    if (activeDemoRun) setSelectedRun(activeDemoRun);
  }, [activeDemoRun, mode]);

  useEffect(() => {
    if (mode === "live" && (!selectedRun || !snap.runs[selectedRun])) setSelectedRun(pickLiveRun(snap));
  }, [mode, snap, selectedRun]);

  useEffect(() => {
    source.follow(selectedRun);
  }, [source, selectedRun]);

  useEffect(() => {
    const url = new URL(location.href);
    url.searchParams.set("mode", mode);
    history.replaceState(null, "", url);
  }, [mode]);

  // Presenter keys: 1–3 switch views, space pauses the replay.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && e.target.closest("input, select, textarea, dialog, .xterm")) return;
      const v = VIEWS.find((x) => x.key === e.key);
      if (v) setView(v.id);
      if (e.key === " " && mode === "demo" && replay) {
        e.preventDefault();
        demo.setPlaying(!replay.playing);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [demo, mode, replay]);

  const runOptions = Object.values(snap.runs).sort((a, b) =>
    (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""),
  );

  return (
    <div className="app">
      <header className="topbar">
        <p className="brand">
          <Logo className="brand-logo" />
          <span className="brand-name">MCP Eval</span>
        </p>
        <nav className="tabs" aria-label="Vistas">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              type="button"
              className={`tab ${view === v.id ? "tab-on" : ""}`}
              aria-current={view === v.id ? "page" : undefined}
              onClick={() => setView(v.id)}
            >
              {v.label}
            </button>
          ))}
        </nav>
        <label className="run-picker">
          <span>Análisis de</span>
          <select value={selectedRun ?? ""} onChange={(e) => setSelectedRun(e.target.value || null)}>
            {runOptions.length === 0 && <option value="">Todavía no hay análisis</option>}
            {runOptions.map((r) => (
              <option key={r.metadata.name} value={r.metadata.name}>
                {runLabel(r)}
              </option>
            ))}
          </select>
        </label>
        <div className="theme-toggle" role="radiogroup" aria-label="Tema">
          {(["light", "dark"] as Theme[]).map((t) => (
            <button
              key={t}
              type="button"
              role="radio"
              aria-checked={theme === t}
              className={`theme ${theme === t ? "theme-on" : ""}`}
              onClick={() => setTheme(t)}
            >
              {t === "light" ? "Claro" : "Oscuro"}
            </button>
          ))}
        </div>
        <div className="mode-toggle" role="radiogroup" aria-label="Fuente de datos">
          {(["demo", "live"] as Mode[]).map((m) => (
            <button
              key={m}
              type="button"
              role="radio"
              aria-checked={mode === m}
              className={`mode mode-${m} ${mode === m ? "mode-on" : ""}`}
              onClick={() => setMode(m)}
            >
              {m === "demo" ? "Demo" : "Live"}
            </button>
          ))}
        </div>
      </header>

      {mode === "demo" && replay && <ReplayBar demo={demo} replay={replay} />}
      {mode === "live" && (
        <div className={`live-bar live-${snap.connection.state}`} role="status">
          {snap.connection.state === "open" && "Conectado al cluster. Los datos llegan con watch sobre los CRs."}
          {snap.connection.state === "connecting" && "Conectando con el backend live…"}
          {snap.connection.state === "error" && snap.connection.message}
        </div>
      )}

      <main className="stage">
        {view === "analysis" && <AnalysisView snap={snap} runName={selectedRun} />}
        {view === "servers" && <ServersView snap={snap} onOpen={setOpenServer} />}
        {/* Kept mounted once opened: disposing xterm with writes still queued
            throws inside xterm ("reading 'dimensions'"). */}
        {termOpened && (
          <div hidden={view !== "terminal"}>
            <TerminalView snap={snap} runName={selectedRun} mode={mode} theme={theme} />
          </div>
        )}
      </main>

      {openServer && (
        <ServerDetail
          key={openServer}
          snap={snap}
          name={openServer}
          onClose={() => setOpenServer(null)}
          onShowRun={(run) => {
            setSelectedRun(run);
            setOpenServer(null);
            setView("analysis");
          }}
        />
      )}
    </div>
  );
}
