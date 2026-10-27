import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useEffect, useRef } from "react";
import type { Theme } from "../components/theme.ts";
import type { Mode, Snapshot } from "../data/source.ts";
import { isTerminal } from "../model/crd.ts";
import { formatForTerminal } from "../model/logs.ts";

// Mirrors the tokens in styles/tokens.css; xterm needs literal colours.
const THEME = {
  background: "#1a1a18",
  foreground: "#f4f4f0",
  cursor: "#1a1a18",
  selectionBackground: "#3c3c36",
  black: "#1a1a18",
  red: "#f0614f",
  green: "#9fe1cb",
  yellow: "#f7a396",
  blue: "#c9c9c0",
  magenta: "#f7a396",
  cyan: "#9fe1cb",
  white: "#f4f4f0",
  brightBlack: "#8b8b82",
  brightRed: "#f58676",
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
      fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
      fontSize: 13,
      lineHeight: 1.25,
      theme: THEME,
    });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(host.current);
    term.current = t;
    written.current = { run: null, count: 0 };
    // Fit only once the host has a laid-out size, and never after dispose:
    // fitting synchronously on mount measured a 0×0 box (blank terminal) and a
    // StrictMode remount let xterm's queued viewport sync hit a disposed
    // renderer ("reading 'dimensions'").
    let disposed = false;
    let frame = 0;
    const refit = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        if (!disposed && host.current && host.current.clientWidth > 0) fit.fit();
      });
    };
    const observer = new ResizeObserver(refit);
    observer.observe(host.current);
    refit();
    return () => {
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      term.current = null;
      // xterm's viewport schedules a sync right after open(); disposing in the
      // same tick (StrictMode's mount-unmount-mount) makes that sync throw.
      setTimeout(() => t.dispose(), 100);
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

  return (
    <section className="terminal panel" aria-label="Registro técnico">
      <header className="terminal-head">
        <p>
          El registro del evaluador, tal como lo escribe: qué agente corre, qué revisa Vigil, cuánto tarda cada paso.
          Prompts y credenciales ya vienen enmascarados.
        </p>
        <p className={`terminal-status ${following ? "terminal-live" : ""}`}>
          {!runName ? "Sin análisis" : following ? "Siguiendo en vivo" : `${lines.length} líneas`}
        </p>
      </header>
      <div className="terminal-frame">
        <div ref={host} className="terminal-host" />
        {runName && lines.length === 0 && (
          <p className="terminal-empty">
            {mode === "live"
              ? "No hay líneas: el registro existe mientras corre la evaluación y hasta 10 minutos después."
              : "El evaluador arranca cuando termina de copiar el código."}
          </p>
        )}
      </div>
    </section>
  );
}
