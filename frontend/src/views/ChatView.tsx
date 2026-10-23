import { type FormEvent, useEffect, useRef, useState } from "react";
import type { Mode } from "../data/source.ts";
import { type ChatReply, detectorLabel } from "../model/chat.ts";
import { friendlyDuration, friendlyModel } from "../model/story.ts";

interface Turn {
  id: number;
  question: string;
  reply?: ChatReply;
  error?: string;
}

const SESSION_KEY = "mcp-eval-ui.chat-session";

function loadSession(): string | null {
  try {
    return sessionStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

function saveSession(id: string | null): void {
  try {
    if (id) sessionStorage.setItem(SESSION_KEY, id);
    else sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // Not persisted; the conversation still works until reload.
  }
}

const EXAMPLES = [
  "¿Qué es un servidor MCP, en una frase?",
  "Mi mail es ana.perez@example.com y mi token ghp_1234567890abcdefghijklmnopqrstuvwxyzAB, ¿los ves?",
  "¿Por qué conviene revisar las descripciones de las herramientas antes de usarlas?",
];

export function ChatView({ mode }: { mode: Mode }) {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [text, setText] = useState("");
  const [pending, setPending] = useState(false);
  const session = useRef<string | null>(loadSession());
  const nextId = useRef(1);
  const logEnd = useRef<HTMLLIElement>(null);

  useEffect(() => {
    logEnd.current?.scrollIntoView({ block: "nearest" });
  }, [turns]);

  const ask = async (question: string) => {
    const id = nextId.current++;
    setTurns((t) => [...t, { id, question }]);
    setSelected(id);
    setPending(true);
    setText("");
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ session: session.current, text: question }),
      });
      const body = (await res.json()) as ChatReply & { error?: string; resetSession?: boolean };
      if (!res.ok) {
        if (body.resetSession) {
          session.current = null;
          saveSession(null);
        }
        throw new Error(body.error ?? `HTTP ${res.status}`);
      }
      session.current = body.session;
      saveSession(body.session);
      setTurns((t) => t.map((x) => (x.id === id ? { ...x, reply: body } : x)));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setTurns((t) => t.map((x) => (x.id === id ? { ...x, error: message } : x)));
    } finally {
      setPending(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const q = text.trim();
    if (q && !pending) void ask(q);
  };

  const restart = () => {
    session.current = null;
    saveSession(null);
    setTurns([]);
    setSelected(null);
  };

  const shown = turns.find((t) => t.id === selected) ?? turns[turns.length - 1];
  const live = mode === "live";

  return (
    <div className="chat">
      <section className="chat-talk" aria-label="Conversación">
        <header className="chat-head">
          <h1>Preguntale al modelo</h1>
          <p>
            Es el mismo camino que usan los agentes de la evaluación: OpenCode arma la consulta, Occludra tapa los datos
            sensibles y el LFM responde desde la GPU de la PC. A la derecha ves por dónde pasó cada respuesta.
          </p>
        </header>

        {!live && (
          <p className="chat-notice">
            El chat usa el modelo de verdad, así que solo funciona en modo Live (arriba a la derecha).
          </p>
        )}

        <ol className="chat-log">
          {turns.length === 0 && live && (
            <li className="chat-empty">
              <p>Probá con algo así:</p>
              <ul>
                {EXAMPLES.map((q) => (
                  <li key={q}>
                    <button type="button" className="chat-example" onClick={() => void ask(q)} disabled={pending}>
                      {q}
                    </button>
                  </li>
                ))}
              </ul>
              <p className="chat-hint">El segundo ejemplo tiene un email y un token: mirá qué hace Occludra con ellos.</p>
            </li>
          )}
          {turns.map((t) => (
            <li key={t.id} className={`turn ${shown?.id === t.id ? "turn-on" : ""}`}>
              <p className="bubble bubble-you">{t.question}</p>
              <button
                type="button"
                className="bubble bubble-model"
                onClick={() => setSelected(t.id)}
                aria-pressed={shown?.id === t.id}
                aria-label="Ver el recorrido de esta respuesta"
              >
                {t.error ? (
                  <span className="bubble-error">{t.error}</span>
                ) : t.reply ? (
                  <span className="bubble-text">{t.reply.text || (t.reply.error ? `Error del modelo: ${t.reply.error}` : "(respuesta vacía)")}</span>
                ) : (
                  <span className="bubble-wait">El modelo está pensando…</span>
                )}
              </button>
            </li>
          ))}
          <li ref={logEnd} aria-hidden="true" />
        </ol>

        <form className="chat-form" onSubmit={onSubmit}>
          <label htmlFor="chat-input" className="sr-only">
            Tu pregunta
          </label>
          <textarea
            id="chat-input"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) onSubmit(e);
            }}
            rows={2}
            maxLength={4000}
            placeholder={live ? "Escribí una pregunta. Enter manda, Shift+Enter baja de línea." : "Pasá a Live para chatear."}
            disabled={!live}
          />
          <div className="chat-actions">
            <button type="submit" className="chat-send" disabled={!live || pending || !text.trim()}>
              {pending ? "Esperando…" : "Preguntar"}
            </button>
            {turns.length > 0 && (
              <button type="button" className="chat-restart" onClick={restart} disabled={pending}>
                Empezar de nuevo
              </button>
            )}
          </div>
        </form>
      </section>

      <aside className="chat-path" aria-label="Recorrido de la respuesta">
        <h2>Recorrido de la respuesta</h2>
        {shown ? <Path turn={shown} /> : <p className="chat-path-empty">Cuando mandes una pregunta, acá vas a ver cada lugar por el que pasó.</p>}
        <p className="chat-path-note">
          NetBird no aparece: ese túnel es para la caja aislada de las evaluaciones, donde corre código desconocido. El chat
          no ejecuta nada, así que habla con Occludra por la red interna del cluster.
        </p>
      </aside>
    </div>
  );
}

function Path({ turn }: { turn: Turn }) {
  const r = turn.reply;
  const calls = r?.gateway ?? null;
  const waiting = !r && !turn.error;
  const masked = (calls ?? []).reduce((acc, c) => {
    for (const [k, n] of Object.entries(c.redactions)) acc[k] = (acc[k] ?? 0) + n;
    return acc;
  }, {} as Record<string, number>);
  const maskedTotal = Object.values(masked).reduce((a, b) => a + b, 0);
  const blocked = calls?.find((c) => c.blockedBy);
  const upstream = calls?.find((c) => c.upstream)?.upstream;
  const modelMs = calls?.reduce((a, c) => a + c.durationMs, 0);
  const state = (done: boolean): HopState => (turn.error ? "fail" : waiting ? "wait" : done ? "ok" : "skip");

  const hops: Hop[] = [
    {
      name: "Tu navegador",
      did: "Manda la pregunta al servidor de la UI, que corre dentro del cluster. Llegás a él por el port-forward.",
      state: "ok",
    },
    {
      name: "OpenCode",
      did: "Arma la conversación con unas instrucciones cortas. No tiene herramientas: no puede leer archivos, ejecutar comandos ni navegar.",
      detail: r ? `sesión ${r.session.slice(0, 16)}…` : undefined,
      state: state(true),
    },
    {
      name: "Occludra",
      did: blocked
        ? `Bloqueó el envío: encontró ${detectorLabel(blocked.blockedBy!)} y la política dice no mandarlo.`
        : calls === null
          ? r
            ? "No se pudo leer su registro, pero todo pasa por acá: es la única salida hacia el modelo."
            : "Tapa emails, tokens, contraseñas y otros datos antes de que salgan."
          : maskedTotal > 0
            ? `Tapó ${maskedTotal} ${maskedTotal === 1 ? "dato" : "datos"} antes de mandar: ${Object.entries(masked)
                .map(([k, n]) => `${n} ${detectorLabel(k)}`)
                .join(", ")}. El modelo recibió [REDACTED] en su lugar.`
            : "Revisó la consulta y no encontró datos sensibles para tapar.",
      detail: calls?.length ? `${calls.length} ${calls.length === 1 ? "llamada" : "llamadas"} al modelo, ${kb(calls.reduce((a, c) => a + c.requestBytes, 0))} enviados` : undefined,
      state: blocked ? "warn" : state(true),
    },
    {
      name: "Salida a la PC",
      did: `Sale del cluster por la VPN (ZeroTier) hacia la PC${upstream ? ` (${upstream})` : ""}. Nada va a un servicio en la nube.`,
      state: blocked ? "skip" : state(!!calls?.length || !!r),
    },
    {
      name: friendlyModel(r?.model ?? "local/lfm"),
      did: waiting ? "Pensando…" : r ? "Respondió." : "No llegó a responder.",
      detail: r
        ? [modelMs !== undefined ? `tardó ${friendlyDuration(modelMs)}` : undefined, `${r.tokens.input} tokens leídos, ${r.tokens.output} escritos`]
            .filter(Boolean)
            .join(", ")
        : undefined,
      state: blocked ? "skip" : state(!!r && !r.error),
    },
    {
      name: "Vuelta",
      did: r ? "La respuesta vuelve por el mismo camino hasta tu pantalla. Occludra no la modifica." : "Esperando la respuesta.",
      detail: r ? `${friendlyDuration(r.totalMs)} en total` : undefined,
      state: state(!!r),
    },
  ];

  return (
    <ol className="path">
      {hops.map((h, i) => (
        <li key={i} className={`hop hop-${h.state}`}>
          <span className="hop-dot" aria-hidden="true" />
          <div>
            <p className="hop-title">{h.name}</p>
            <p className="hop-text">{h.did}</p>
            {h.detail && <p className="hop-detail">{h.detail}</p>}
          </div>
        </li>
      ))}
      {turn.error && <li className="path-error">{turn.error}</li>}
    </ol>
  );
}

type HopState = "ok" | "wait" | "warn" | "fail" | "skip";

interface Hop {
  name: string;
  did: string;
  detail?: string;
  state: HopState;
}

function kb(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}
