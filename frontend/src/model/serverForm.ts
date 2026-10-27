// The "evaluate a server" form: field rules shared by the browser (inline
// errors) and server/actions.ts (the check that counts). Everything that ends
// up in an MCPServer spec goes through validateServerForm.
import { API_VERSION, type MCPServer, type Transport } from "./crd.ts";

export type SchedulePreset = "6h" | "daily" | "weekly";

export const SCHEDULES: { id: SchedulePreset; label: string; cron: string }[] = [
  { id: "6h", label: "Cada 6 horas", cron: "0 */6 * * *" },
  { id: "daily", label: "Todos los días, 3:00 UTC", cron: "0 3 * * *" },
  { id: "weekly", label: "Los lunes, 3:00 UTC", cron: "0 3 * * 1" },
];

/** Label put on servers the UI creates; servers without it come from git (Flux). */
export const LABEL_MANAGED_BY = "app.kubernetes.io/managed-by";
export const MANAGED_BY_UI = "mcp-eval-ui";
/** Flux marks what it applies; the UI must not pause or delete those (Flux would undo it). */
export const LABEL_FLUX = "kustomize.toolkit.fluxcd.io/name";

/** Persona names in run order, as config/samples defines them. */
export const DEFAULT_SUITE = ["mcp-sast-auditor", "mcp-fuzz-tester", "mcp-rogue-detector", "mcp-synthesizer"];

/** Upper bound of servers the UI may create, so a leaked password cannot flood the cluster. */
export const MAX_UI_SERVERS = 20;

export interface ServerForm {
  name: string;
  repositoryUrl: string;
  ref: string;
  path: string;
  transport: Transport;
  targetPort: string;
  schedule: SchedulePreset;
}

export const EMPTY_FORM: ServerForm = {
  name: "",
  repositoryUrl: "",
  ref: "main",
  path: "",
  transport: "stdio",
  targetPort: "8080",
  schedule: "daily",
};

export type FormErrors = Partial<Record<keyof ServerForm, string>>;

// Runs are named <server>-run-xxxxx and their Jobs <run>-job: keep room for
// both inside the 63-character label limit.
const NAME = /^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$/;
const REPO = /^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?\/[A-Za-z0-9._~\-/]+$/;
const REF = /^[A-Za-z0-9._\-/]{1,100}$/;
const PATH = /^[A-Za-z0-9._\-/]{0,200}$/;

/** A name suggestion from the repository URL: github.com/acme/weather-mcp -> weather-mcp. */
export function suggestName(repositoryUrl: string): string {
  const last = repositoryUrl.replace(/\.git$/, "").replace(/\/+$/, "").split("/").pop() ?? "";
  return last
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/, "");
}

export function validateServerForm(form: ServerForm, existing: Iterable<string> = []): FormErrors {
  const errors: FormErrors = {};
  const taken = new Set(existing);
  if (!NAME.test(form.name)) {
    errors.name = "Usá minúsculas, números y guiones (hasta 40 caracteres), sin guion al principio ni al final.";
  } else if (taken.has(form.name)) {
    errors.name = "Ya hay un servidor con ese nombre.";
  }
  if (!REPO.test(form.repositoryUrl) || form.repositoryUrl.length > 300) {
    errors.repositoryUrl = "Pegá la dirección https del repositorio, por ejemplo https://github.com/org/servidor.";
  }
  if (!REF.test(form.ref)) errors.ref = "Escribí una rama, tag o commit (por ejemplo main).";
  if (!PATH.test(form.path) || form.path.split("/").includes("..") || form.path.startsWith("/")) {
    errors.path = "Una carpeta dentro del repositorio, sin .. ni / al principio. Dejalo vacío si el servidor está en la raíz.";
  }
  if (form.transport !== "stdio" && form.transport !== "sse") errors.transport = "Elegí stdio o SSE.";
  if (form.transport === "sse") {
    const port = Number(form.targetPort);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) errors.targetPort = "Un puerto entre 1024 y 65535.";
  }
  if (!SCHEDULES.some((s) => s.id === form.schedule)) errors.schedule = "Elegí cada cuánto evaluarlo.";
  return errors;
}

/** The MCPServer the form creates. Assumes validateServerForm returned no errors. */
export function serverFromForm(form: ServerForm, namespace: string, suite: string[]): MCPServer {
  const cron = SCHEDULES.find((s) => s.id === form.schedule)!.cron;
  return {
    apiVersion: API_VERSION,
    kind: "MCPServer",
    metadata: {
      name: form.name,
      namespace,
      labels: { [LABEL_MANAGED_BY]: MANAGED_BY_UI },
      // Evaluate right away instead of waiting for the first scheduled slot.
      annotations: { "security.eval.io/trigger-now": "true" },
    },
    spec: {
      repositoryUrl: form.repositoryUrl,
      ref: form.ref,
      ...(form.path ? { path: form.path } : {}),
      transport: form.transport,
      ...(form.transport === "sse" ? { targetPort: Number(form.targetPort) } : {}),
      schedule: cron,
      active: true,
      agentSuite: suite.map((name) => ({ name })),
      timeoutSeconds: 1800,
      runHistoryLimit: 5,
    },
  };
}

export function isGitManaged(server: MCPServer): boolean {
  return !!server.metadata.labels?.[LABEL_FLUX] && server.metadata.labels?.[LABEL_MANAGED_BY] !== MANAGED_BY_UI;
}

/** "0 3 * * *" -> "Todos los días a las 3:00"; anything else is shown as cron. */
export function describeSchedule(cron: string | undefined): string {
  if (!cron) return "Sin programar";
  const preset = SCHEDULES.find((s) => s.cron === cron)?.label;
  if (preset) return preset;
  const every = /^\*\/(\d+) \* \* \* \*$/.exec(cron) ?? /^0 \*\/(\d+) \* \* \*$/.exec(cron);
  if (every) return `Cada ${every[1]} ${cron.startsWith("*/") ? "minutos" : "horas"}`;
  return `Programado: ${cron}`;
}
