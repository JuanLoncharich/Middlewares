// Browser side of server/actions.ts. Errors come back as Spanish sentences
// ready to show; field errors keep the form's keys.
import type { FormErrors, ServerForm } from "../model/serverForm.ts";

export class ActionError extends Error {
  constructor(
    message: string,
    readonly fields?: FormErrors,
  ) {
    super(message);
  }
}

async function call(method: string, path: string, body?: unknown): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ActionError("No hay conexión con el servidor de la UI.");
  }
  const data = (await res.json().catch(() => ({}))) as { error?: string; fields?: FormErrors };
  if (!res.ok) throw new ActionError(data.error ?? `Falló (HTTP ${res.status}).`, data.fields);
  return data;
}

export const actions = {
  create: (form: ServerForm) => call("POST", "/api/servers", form) as Promise<{ name: string }>,
  evaluate: (name: string) => call("POST", `/api/servers/${encodeURIComponent(name)}/evaluate`),
  setPaused: (name: string, paused: boolean) => call("POST", `/api/servers/${encodeURIComponent(name)}/pause`, { paused }),
  remove: (name: string) => call("DELETE", `/api/servers/${encodeURIComponent(name)}`),
};
