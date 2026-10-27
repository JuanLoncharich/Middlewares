import { useEffect, useMemo, useRef, useState } from "react";
import { Logo } from "./components/Logo.tsx";
import { ReplayBar } from "./components/ReplayBar.tsx";
import { type Theme, applyTheme, initialTheme } from "./components/theme.ts";
import { DemoSource } from "./data/demo/replay.ts";
import { useReplay, useSnapshot } from "./data/hooks.ts";
import { LiveSource } from "./data/live.ts";
import type { Mode } from "./data/source.ts";
import { go, href, useRoute } from "./router.ts";
import { HowItWorks } from "./views/HowItWorks.tsx";
import { NewServerSheet } from "./views/NewServerSheet.tsx";
import { ServerPage } from "./views/ServerPage.tsx";
import { ServersPage } from "./views/ServersPage.tsx";
import "./styles/shell.css";
import "./styles/pages.css";
import "./styles/story.css";
import "./styles/chat.css";

/** Live by default where the UI is deployed; the demo replay for `npm run demo`. */
function initialMode(): Mode {
  const asked = new URLSearchParams(location.search).get("mode");
  if (asked === "live" || asked === "demo") return asked;
  return import.meta.env.MODE === "development" ? "demo" : "live";
}

export function App() {
  const demo = useMemo(() => new DemoSource(), []);
  const live = useMemo(() => new LiveSource(), []);
  const [mode, setMode] = useState<Mode>(initialMode);
  const source = mode === "demo" ? demo : live;
  const snap = useSnapshot(source);
  const replay = useReplay(mode === "demo" ? demo : null);
  const route = useRoute();
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [creating, setCreating] = useState(false);

  useEffect(() => applyTheme(theme), [theme]);

  useEffect(() => {
    source.start();
    return () => source.stop();
  }, [source]);

  useEffect(() => {
    const url = new URL(location.href);
    url.searchParams.set("mode", mode);
    history.replaceState(null, "", url);
  }, [mode]);

  // The demo replays one scenario at a time: open its server so the story is on screen.
  const activeDemoRun = mode === "demo" ? demo.activeRun : null;
  const demoServer = activeDemoRun ? snap.runs[activeDemoRun]?.spec.serverRef : undefined;
  const lastDemoServer = useRef(demoServer);
  useEffect(() => {
    // Follow a scenario switch, but never override the page someone opened by link.
    const changed = lastDemoServer.current !== undefined && lastDemoServer.current !== demoServer;
    lastDemoServer.current = demoServer;
    if (changed && demoServer && route.page === "server") go({ page: "server", server: demoServer, run: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demoServer]);

  const conn = snap.connection;

  return (
    <div className="shell">
      <aside className="rail">
        <a className="brand" href={href({ page: "servers" })}>
          <Logo className="brand-logo" />
          <span>MCP Eval</span>
        </a>
        <nav className="nav" aria-label="Secciones">
          <a href={href({ page: "servers" })} aria-current={route.page !== "how" ? "page" : undefined}>
            Servidores
          </a>
          <a href={href({ page: "how" })} aria-current={route.page === "how" ? "page" : undefined}>
            Cómo funciona
          </a>
        </nav>
        <div className="rail-foot">
          <p className={`conn conn-${mode === "demo" ? "demo" : conn.state}`} role="status">
            {mode === "demo"
              ? "Datos de demostración"
              : conn.state === "open"
                ? "Conectado al cluster"
                : conn.state === "connecting"
                  ? "Conectando…"
                  : "Sin conexión con el cluster"}
          </p>
          <div className="seg" role="radiogroup" aria-label="Fuente de datos">
            {(["live", "demo"] as Mode[]).map((m) => (
              <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}>
                {m === "live" ? "Cluster" : "Demo"}
              </button>
            ))}
          </div>
          <div className="seg" role="radiogroup" aria-label="Tema">
            {(["light", "dark"] as Theme[]).map((t) => (
              <button key={t} type="button" role="radio" aria-checked={theme === t} onClick={() => setTheme(t)}>
                {t === "light" ? "Claro" : "Oscuro"}
              </button>
            ))}
          </div>
        </div>
      </aside>

      <main className="main">
        {mode === "demo" && replay && <ReplayBar demo={demo} replay={replay} />}
        {mode === "live" && conn.state === "error" && (
          <p className="notice notice-error banner" role="alert">
            {conn.message ?? "Se perdió la conexión con el cluster."} Reintentando…
          </p>
        )}
        {route.page === "servers" && <ServersPage snap={snap} onNew={() => setCreating(true)} />}
        {route.page === "server" && (
          <ServerPage snap={snap} source={source} mode={mode} theme={theme} name={route.server} runName={route.run} />
        )}
        {route.page === "how" && <HowItWorks mode={mode} />}
      </main>

      {creating && (
        <NewServerSheet
          demo={mode === "demo"}
          existing={Object.keys(snap.servers)}
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false);
            go({ page: "server", server: name, run: null });
          }}
        />
      )}
    </div>
  );
}
