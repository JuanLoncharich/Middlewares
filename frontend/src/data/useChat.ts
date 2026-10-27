// One conversation with the model through /api/chat. `run` ties it to an
// analysis ("preguntale al análisis"): the backend then opens the session with
// that run's data. Without a run it is the plain path demo.
import { useCallback, useRef, useState } from "react";
import type { ChatReply } from "../model/chat.ts";

export interface Turn {
  id: number;
  question: string;
  reply?: ChatReply;
  error?: string;
}

function storageKey(run: string | null): string {
  return run ? `mcp-eval-ui.chat.${run}` : "mcp-eval-ui.chat-session";
}

function load(key: string): string | null {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function save(key: string, id: string | null): void {
  try {
    if (id) sessionStorage.setItem(key, id);
    else sessionStorage.removeItem(key);
  } catch {
    // Not persisted; the conversation still works until reload.
  }
}

export function useChat(run: string | null) {
  const key = storageKey(run);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [pending, setPending] = useState(false);
  const session = useRef<string | null>(load(key));
  const nextId = useRef(1);

  const ask = useCallback(
    async (question: string) => {
      const id = nextId.current++;
      setTurns((t) => [...t, { id, question }]);
      setPending(true);
      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ session: session.current, text: question, ...(run ? { run } : {}) }),
        });
        const body = (await res.json()) as ChatReply & { error?: string; resetSession?: boolean };
        if (!res.ok) {
          if (body.resetSession) {
            session.current = null;
            save(key, null);
          }
          throw new Error(body.error ?? `HTTP ${res.status}`);
        }
        session.current = body.session;
        save(key, body.session);
        setTurns((t) => t.map((x) => (x.id === id ? { ...x, reply: body } : x)));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setTurns((t) => t.map((x) => (x.id === id ? { ...x, error: message } : x)));
      } finally {
        setPending(false);
      }
    },
    [key, run],
  );

  const restart = useCallback(() => {
    session.current = null;
    save(key, null);
    setTurns([]);
  }, [key]);

  return { turns, pending, ask, restart };
}
