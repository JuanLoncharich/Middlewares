// Shapes shared by the chat backend (server/chat.ts) and the chat view.

/** One inference request as Occludra's journal records it: metadata, never content. */
export interface GatewayHop {
  id: number;
  at: string;
  client: string;
  model?: string;
  redactions: Record<string, number>;
  blockedBy?: string;
  status: number;
  /** host:port of the upstream model server. */
  upstream?: string;
  servedBy?: string;
  durationMs: number;
  requestBytes: number;
  responseBytes: number;
}

export interface ChatReply {
  session: string;
  text: string;
  error?: string;
  model: string;
  tokens: { input: number; output: number };
  /** Browser-side backend: from receiving the question to having the answer. */
  totalMs: number;
  /** OpenCode's own clock for the assistant message. */
  opencodeMs?: number;
  /** Model calls the message caused, as Occludra saw them; null when the journal is unreachable. */
  gateway: GatewayHop[] | null;
}

/** Plain-language names for Occludra's detectors (manifests/occludra-deployment.yaml). */
export const DETECTOR_LABEL: Record<string, string> = {
  email: "email",
  "us-ssn": "número de seguro social",
  "phone-intl": "teléfono",
  iban: "cuenta bancaria (IBAN)",
  "api-key": "clave de API",
  "bearer-token": "token de acceso",
  "password-context": "contraseña",
  "secret-assignment": "secreto en código",
  "person-name-context": "nombre de persona",
  "large-amount": "monto grande",
  "currency-amount": "monto de dinero",
};

export function detectorLabel(name: string): string {
  return DETECTOR_LABEL[name] ?? name;
}
