import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useRef } from "react";
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
}

export function TerminalView({ snap, runName, mode }: Props) {
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

  const following = run && !isTerminal(run.status?.phase);

  return (
    <section className="view terminal-view" aria-label="Terminal de OpenCode">
      <header className="terminal-head">
        <div>
          <h2>Sesión del evaluator</h2>
          <p className="muted">
            Solo lectura. Es el log del contenedor <code>evaluator</code>, que maneja las sesiones de OpenCode. No hay shell ni entrada: el
            sandbox no acepta comandos desde afuera.
          </p>
        </div>
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
      <p className="muted small">
        Los logs del contenedor <code>target</code> (el servidor no confiable) y del <code>cloner</code> nunca se muestran. El runner ya enmascara
        prompts, payloads y credenciales antes de escribir cada línea.
      </p>
    </section>
  );
}
