// Pieces shared by the two chats: the conversation (log + box) and the path
// one answer took (browser -> OpenCode -> Occludra -> the PC -> the model).
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import type { Turn } from "../data/useChat.ts";
import { detectorLabel } from "../model/chat.ts";
import { friendlyDuration, friendlyModel } from "../model/story.ts";

interface ConversationProps {
  turns: Turn[];
  pending: boolean;
  enabled: boolean;
  disabledReason?: string;
  examples: string[];
  intro?: ReactNode;
  placeholder: string;
  selected: number | null;
  onSelect: (id: number) => void;
  onAsk: (q: string) => void;
  onRestart: () => void;
}

export function Conversation(p: ConversationProps) {
  const [text, setText] = useState("");
  const end = useRef<HTMLLIElement>(null);
  useEffect(() => {
    end.current?.scrollIntoView({ block: "nearest" });
  }, [p.turns]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const q = text.trim();
    if (!q || p.pending || !p.enabled) return;
    setText("");
    p.onAsk(q);
  };
  return (
    <div className="convo">
      {!p.enabled && p.disabledReason && <p className="notice">{p.disabledReason}</p>}
      <ol className="convo-log">
        {p.turns.length === 0 && p.enabled && (
          <li className="convo-empty">
            {p.intro}
            <ul>
              {p.examples.map((q) => (
                <li key={q}>
                  <button type="button" className="convo-example" onClick={() => p.onAsk(q)} disabled={p.pending}>
                    {q}
                  </button>
                </li>
              ))}
            </ul>
          </li>
        )}
        {p.turns.map((t) => (
          <li key={t.id} className={`turn ${p.selected === t.id ? "turn-on" : ""}`}>
            <p className="bubble bubble-you">{t.question}</p>
            <button
              type="button"
              className="bubble bubble-model"
              onClick={() => p.onSelect(t.id)}
              aria-pressed={p.selected === t.id}
              aria-label="Ver el recorrido de esta respuesta"
            >
              {t.error ? (
                <span className="bubble-error">{t.error}</span>
              ) : t.reply ? (
                <span>{t.reply.text || (t.reply.error ? `Error del modelo: ${t.reply.error}` : "(respuesta vacía)")}</span>
              ) : (
                <span className="bubble-wait">Pensando…</span>
              )}
            </button>
          </li>
        ))}
        <li ref={end} aria-hidden="true" />
      </ol>
      <form className="convo-form" onSubmit={submit}>
        <label className="sr-only" htmlFor={`q-${p.placeholder.length}`}>
          Tu pregunta
        </label>
        <textarea
          id={`q-${p.placeholder.length}`}
          className="textarea"
          value={text}
          rows={2}
          maxLength={4000}
          disabled={!p.enabled}
          placeholder={p.placeholder}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) submit(e);
          }}
        />
        <div className="convo-actions">
          <button type="submit" className="btn btn-primary" disabled={!p.enabled || p.pending || !text.trim()}>
            {p.pending ? "Esperando…" : "Preguntar"}
          </button>
          {p.turns.length > 0 && (
            <button type="button" className="btn btn-ghost" onClick={p.onRestart} disabled={p.pending}>
              Empezar de nuevo
            </button>
          )}
        </div>
      </form>
    </div>
  );
}

/** "Occludra tapó 2 datos (1 email, 1 clave de API)" for one answer, or null. */
export function maskedSummary(turn: Turn): string | null {
  const calls = turn.reply?.gateway;
  if (!calls) return null;
  const masked: Record<string, number> = {};
  for (const c of calls) for (const [k, n] of Object.entries(c.redactions)) masked[k] = (masked[k] ?? 0) + n;
  const total = Object.values(masked).reduce((a, b) => a + b, 0);
  if (total === 0) return "Occludra revisó lo que se mandó al modelo y no encontró datos sensibles.";
  return `Occludra tapó ${total} ${total === 1 ? "dato" : "datos"} antes de mandarlo al modelo: ${Object.entries(masked)
    .map(([k, n]) => `${n} ${detectorLabel(k)}`)
    .join(", ")}.`;
}

export function Path({ turn }: { turn: Turn }) {
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
      did: "Manda la pregunta al servidor de la UI, que corre dentro del cluster. Entra por Traefik, que pide tu usuario y contraseña.",
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
