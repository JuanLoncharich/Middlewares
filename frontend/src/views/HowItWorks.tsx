import { useEffect, useState } from "react";
import { Conversation, Path } from "../components/ChatParts.tsx";
import type { Mode } from "../data/source.ts";
import { useChat } from "../data/useChat.ts";

const STAGES: { name: string; what: string }[] = [
  {
    name: "Caja aislada",
    what: "El código del servidor se copia y se arranca en un contenedor sin internet. Solo puede hablar con los detectores de la plataforma.",
  },
  {
    name: "Vigil",
    what: "Lee todo lo que el servidor le diría a una IA (nombres y descripciones de herramientas, respuestas) y busca instrucciones escondidas. Si dos detectores coinciden, corta todo.",
  },
  {
    name: "Cuatro agentes de IA",
    what: "Uno lee el código, otro lo prueba con pedidos raros, otro intenta que se porte mal y el último junta todo en un veredicto.",
  },
  {
    name: "Occludra",
    what: "Es la única salida hacia el modelo. Antes de mandar código o respuestas del servidor, tapa claves, tokens, emails y otros datos sensibles.",
  },
  {
    name: "El modelo",
    what: "LFM 2.5, en la GPU de una PC del equipo. Nada se manda a un servicio en la nube.",
  },
];

const EXAMPLES = [
  "¿Qué es un servidor MCP, en una frase?",
  "Mi mail es ana.perez@example.com y mi token ghp_1234567890abcdefghijklmnopqrstuvwxyzAB, ¿los ves?",
];

export function HowItWorks({ mode }: { mode: Mode }) {
  const chat = useChat(null);
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => {
    const last = chat.turns[chat.turns.length - 1];
    if (last) setSelected(last.id);
  }, [chat.turns]);
  const shown = chat.turns.find((t) => t.id === selected);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Cómo funciona</h1>
          <p className="page-lede">
            Un servidor MCP le da herramientas a una IA. Si es malicioso, puede esconder órdenes para esa IA o sacar datos.
            Esta plataforma lo revisa antes de que alguien lo conecte.
          </p>
        </div>
      </header>

      <ol className="stages">
        {STAGES.map((s, i) => (
          <li key={s.name} className="stage panel">
            <span className="stage-n">{i + 1}</span>
            <h2>{s.name}</h2>
            <p>{s.what}</p>
          </li>
        ))}
      </ol>

      <section className="pathdemo" aria-labelledby="pathdemo-title">
        <div className="pathdemo-text">
          <h2 id="pathdemo-title">Probá el camino hasta el modelo</h2>
          <p className="muted">
            Mandá una pregunta y mirá por dónde pasa: es el mismo camino que usan los agentes cuando evalúan un servidor.
            Probá escribir un email o un token para ver qué hace Occludra con ellos.
          </p>
          <Conversation
            turns={chat.turns}
            pending={chat.pending}
            enabled={mode === "live"}
            disabledReason="Funciona en modo Live: le pregunta al modelo de verdad."
            examples={EXAMPLES}
            placeholder="Escribí algo. Enter manda."
            selected={selected}
            onSelect={setSelected}
            onAsk={(q) => void chat.ask(q)}
            onRestart={chat.restart}
          />
        </div>
        <aside className="pathdemo-path panel" aria-label="Recorrido de la respuesta">
          <h3>Recorrido de la respuesta</h3>
          {shown ? <Path turn={shown} /> : <p className="muted">Cuando mandes algo, acá aparece cada lugar por el que pasó.</p>}
        </aside>
      </section>
    </div>
  );
}
