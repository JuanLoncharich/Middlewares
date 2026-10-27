import { useEffect, useState } from "react";
import type { Mode } from "../data/source.ts";
import { useChat } from "../data/useChat.ts";
import { Conversation, maskedSummary } from "./ChatParts.tsx";

const EXAMPLES = [
  "¿Por qué salió este veredicto?",
  "¿Qué tendría que arreglar primero?",
  "¿Lo puedo usar con datos reales?",
];

/** "Preguntale al análisis": a chat whose model has this run's results in front of it. */
export function AskPanel({ run, mode, finished }: { run: string; mode: Mode; finished: boolean }) {
  const chat = useChat(run);
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => {
    const last = chat.turns[chat.turns.length - 1];
    if (last) setSelected(last.id);
  }, [chat.turns]);
  const shown = chat.turns.find((t) => t.id === selected);
  const note = shown ? maskedSummary(shown) : null;

  const reason =
    mode === "demo"
      ? "Funciona en modo Live: le pregunta al modelo de verdad."
      : !finished
        ? "Vas a poder preguntar cuando termine el análisis."
        : undefined;

  return (
    <section className="ask panel" aria-labelledby="ask-title">
      <h2 id="ask-title">Preguntale al análisis</h2>
      <p className="muted ask-lede">
        El modelo lee los resultados de esta evaluación y te los explica. No ve nada más.
      </p>
      <Conversation
        turns={chat.turns}
        pending={chat.pending}
        enabled={!reason}
        disabledReason={reason}
        examples={EXAMPLES}
        placeholder="Preguntá sobre este análisis"
        selected={selected}
        onSelect={setSelected}
        onAsk={(q) => void chat.ask(q)}
        onRestart={chat.restart}
      />
      {note && <p className="ask-note">{note}</p>}
    </section>
  );
}
