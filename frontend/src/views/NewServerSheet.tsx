import { type FormEvent, useEffect, useRef, useState } from "react";
import { ActionError, actions } from "../data/actions.ts";
import { EMPTY_FORM, type FormErrors, SCHEDULES, type ServerForm, suggestName, validateServerForm } from "../model/serverForm.ts";

interface Props {
  /** Demo mode: the form works but nothing is created. */
  demo: boolean;
  existing: string[];
  onClose: () => void;
  onCreated: (name: string) => void;
}

/** "Evaluar un servidor": a side sheet with the form; creates the MCPServer and opens it. */
export function NewServerSheet({ demo, existing, onClose, onCreated }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [form, setForm] = useState<ServerForm>(EMPTY_FORM);
  const [nameTouched, setNameTouched] = useState(false);
  const [errors, setErrors] = useState<FormErrors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    dialog.current?.showModal();
  }, []);

  const set = <K extends keyof ServerForm>(key: K, value: ServerForm[K]) => {
    setForm((f) => {
      const next = { ...f, [key]: value };
      if (key === "repositoryUrl" && !nameTouched) next.name = suggestName(String(value));
      return next;
    });
    setErrors((e) => ({ ...e, [key]: undefined }));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const found = validateServerForm(form, existing);
    setErrors(found);
    setFailure(null);
    if (Object.keys(found).length > 0) return;
    if (demo) {
      setFailure("Esto es la demo: con los datos del cluster (modo Cluster), este botón agrega el servidor y lo evalúa.");
      return;
    }
    setBusy(true);
    try {
      const { name } = await actions.create(form);
      onCreated(name);
    } catch (err) {
      if (err instanceof ActionError && err.fields) setErrors(err.fields);
      setFailure(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const fieldProps = (key: keyof ServerForm) => ({
    id: `f-${key}`,
    "aria-invalid": errors[key] ? true : undefined,
    "aria-describedby": `f-${key}-help`,
  });

  return (
    <dialog ref={dialog} className="sheet" aria-labelledby="sheet-title" onClose={onClose} onCancel={onClose}>
      <form className="sheet-body" onSubmit={submit} noValidate>
        <header className="sheet-head">
          <h2 id="sheet-title">Evaluar un servidor</h2>
          <button type="button" className="btn btn-ghost" onClick={() => dialog.current?.close()} aria-label="Cerrar">
            Cerrar
          </button>
        </header>
        <p className="muted">
          La plataforma copia el código, lo arranca en una caja aislada y lo revisa. La primera evaluación empieza apenas lo
          agregás y tarda unos minutos.
        </p>

        <div className="field">
          <label htmlFor="f-repositoryUrl">Repositorio</label>
          <input
            {...fieldProps("repositoryUrl")}
            className="input"
            type="url"
            inputMode="url"
            placeholder="https://github.com/org/mi-servidor-mcp"
            value={form.repositoryUrl}
            onChange={(e) => set("repositoryUrl", e.target.value.trim())}
            autoFocus
          />
          <p id="f-repositoryUrl-help" className={errors.repositoryUrl ? "error" : "hint"}>
            {errors.repositoryUrl ?? "La dirección https de GitHub, GitLab o similar. Tiene que ser público."}
          </p>
        </div>

        <div className="field">
          <label htmlFor="f-name">Nombre</label>
          <input
            {...fieldProps("name")}
            className="input"
            value={form.name}
            onChange={(e) => {
              setNameTouched(true);
              set("name", e.target.value.toLowerCase());
            }}
          />
          <p id="f-name-help" className={errors.name ? "error" : "hint"}>
            {errors.name ?? "Cómo lo vas a ver en la lista. Se completa solo con el nombre del repositorio."}
          </p>
        </div>

        <div className="field-row">
          <div className="field">
            <label htmlFor="f-ref">Rama, tag o commit</label>
            <input {...fieldProps("ref")} className="input" value={form.ref} onChange={(e) => set("ref", e.target.value.trim())} />
            <p id="f-ref-help" className={errors.ref ? "error" : "hint"}>
              {errors.ref ?? "Normalmente main."}
            </p>
          </div>
          <div className="field">
            <label htmlFor="f-path">Carpeta (opcional)</label>
            <input
              {...fieldProps("path")}
              className="input"
              placeholder="src/servidor"
              value={form.path}
              onChange={(e) => set("path", e.target.value.trim())}
            />
            <p id="f-path-help" className={errors.path ? "error" : "hint"}>
              {errors.path ?? "Si el repositorio tiene varios servidores, en qué carpeta está este."}
            </p>
          </div>
        </div>

        <fieldset className="field">
          <legend>Cómo se conecta</legend>
          <div className="choice-row" role="radiogroup">
            <label className="choice">
              <input type="radio" name="transport" checked={form.transport === "stdio"} onChange={() => set("transport", "stdio")} />
              <span>
                <strong>stdio</strong>
                <span className="hint">Se lanza como un programa. Es lo más común.</span>
              </span>
            </label>
            <label className="choice">
              <input type="radio" name="transport" checked={form.transport === "sse"} onChange={() => set("transport", "sse")} />
              <span>
                <strong>HTTP (SSE)</strong>
                <span className="hint">Escucha en un puerto.</span>
              </span>
            </label>
          </div>
        </fieldset>

        {form.transport === "sse" && (
          <div className="field">
            <label htmlFor="f-targetPort">Puerto</label>
            <input
              {...fieldProps("targetPort")}
              className="input input-short"
              inputMode="numeric"
              value={form.targetPort}
              onChange={(e) => set("targetPort", e.target.value.trim())}
            />
            <p id="f-targetPort-help" className={errors.targetPort ? "error" : "hint"}>
              {errors.targetPort ?? "El puerto donde escucha el servidor dentro de la caja."}
            </p>
          </div>
        )}

        <div className="field">
          <label htmlFor="f-schedule">Volver a evaluarlo</label>
          <select
            {...fieldProps("schedule")}
            className="select"
            value={form.schedule}
            onChange={(e) => set("schedule", e.target.value as ServerForm["schedule"])}
          >
            {SCHEDULES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
          <p id="f-schedule-help" className="hint">
            Un servidor puede cambiar con el tiempo: cada evaluación nueva usa el código de ese momento.
          </p>
        </div>

        {failure && (
          <p className="notice notice-error" role="alert">
            {failure}
          </p>
        )}

        <footer className="sheet-foot">
          <button type="button" className="btn" onClick={() => dialog.current?.close()}>
            Cancelar
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Agregando…" : "Evaluar servidor"}
          </button>
        </footer>
      </form>
    </dialog>
  );
}
