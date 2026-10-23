import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useRef } from "react";
import { PhaseTag } from "../components/Tags.tsx";
import { Tile } from "../components/Bento.tsx";
import type { Theme } from "../components/theme.ts";
import type { Mode, Snapshot } from "../data/source.ts";
import { isTerminal } from "../model/crd.ts";
import { formatForTerminal } from "../model/logs.ts";

// Mirrors the tokens in styles/tokens.css; xterm needs literal colours.
const THEME = {
  background: "#132238",
  foreground: "#e6ecef",
  cursor: "#132238",
  selectionBackground: "#5a6b80",
  black: "#132238",
  red: "#ff8a80",
  green: "#7fd8c4",
  yellow: "#f2c14e",
  blue: "#9cc3ff",
  magenta: "#e3a6ff",
  cyan: "#8fd3ff",
  white: "#e6ecef",
  brightBlack: "#8a9bb0",
  brightRed: "#ff8a80",
};

interface Props {
  snap: Snapshot;
  runName: string | null;
  mode: Mode;
  theme: Theme;
}

export function TerminalView({ snap, runName, mode, theme }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const written = useRef<{ run: string | null; count: number }>({ run: null, count: 0 });
  const lines = (runName && snap.logs[runName]) || [];
  const run = runName ? snap.runs[runName] : undefined;

  useEffect(() => {
    if (!host.current) return;
    const t = new Terminal({
      disableStdin: true,
      cursorBlink: false,
      cursorStyle: "underline",
      convertEol: true,
      scrollback: 5000,
      fontFamily: '"JetBrains Mono Variable", ui-monospace, monospace',
      fontSize: 17,
      lineHeight: 1.25,
      theme: THEME,
    });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(host.current);
    fit.fit();
    term.current = t;
    written.current = { run: null, count: 0 };
    const onResize = () => fit.fit();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      t.dispose();
      term.current = null;
    };
  }, []);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    const w = written.current;
    if (w.run !== runName || lines.length < w.count) {
      t.reset();
      if (runName) t.writeln(`\x1b[2m# kubectl -n mcp-evals logs -f -l security.eval.io/run=${runName} -c evaluator\x1b[0m`);
      written.current = { run: runName, count: 0 };
    }
    for (const line of lines.slice(written.current.count)) t.writeln(formatForTerminal(line));
    written.current.count = lines.length;
  }, [runName, lines]);

  // The terminal is dark in both themes; its background tracks the theme's token.
  useEffect(() => {
    const t = term.current;
    if (!t) return;
    const css = getComputedStyle(document.documentElement);
    const bg = css.getPropertyValue("--terminal-bg").trim() || THEME.background;
    t.options.theme = { ...THEME, background: bg, cursor: bg, black: bg };
  }, [theme]);

  const following = run && !isTerminal(run.status?.phase);
  const phase = run?.status?.phase;

  return (
    <div className="bento view terminal-view" aria-label="Terminal de OpenCode">
      <Tile span={9} rows={3} className="tile-terminal" label="Sesión del evaluator">
        <header className="terminal-head">
          <h2>Sesión del evaluator</h2>
          <p className={`terminal-status ${following ? "terminal-status-live" : ""}`}>
            {!runName ? "Sin run seleccionado" : following ? "Siguiendo en vivo" : `${lines.length} líneas`}
          </p>
        </header>
        <div className="terminal-frame">
          <div ref={host} className="terminal-host" />
          {runName && lines.length === 0 && (
            <p className="terminal-empty">
              {mode === "live"
                ? "Sin líneas todavía. El pod existe desde que arranca el Job y sus logs duran 10 minutos después de terminar."
                : "El evaluator arranca cuando termina el clonado."}
            </p>
          )}
        </div>
      </Tile>

      <Tile span={3} title="Run" tone={following ? "evaluating" : "plain"}>
        {run ? (
          <>
            <p className="side-strong">{run.spec.serverRef}</p>
            <p>
              <PhaseTag phase={phase} />
            </p>
            {run.status?.currentAgent && <p className="small">Ahora corre {run.status.currentAgent}</p>}
          </>
        ) : (
          <p className="muted">Elegí un run arriba.</p>
        )}
      </Tile>
      <Tile span={3} title="Qué ves">
        <p className="small">
          El log del contenedor <code>evaluator</code>, que maneja las sesiones de OpenCode. Es de solo lectura: no hay shell ni entrada.
        </p>
      </Tile>
      <Tile span={3} title="Qué no ves">
        <p className="small">
          Los logs de <code>target</code> (el servidor no confiable) y de <code>cloner</code>. Tampoco prompts ni credenciales: el runner los
          enmascara antes de escribir.
        </p>
      </Tile>
    </div>
  );
}
