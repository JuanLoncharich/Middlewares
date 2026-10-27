import type { Snapshot } from "../data/source.ts";
import type { Finding } from "../model/crd.ts";
import type { Redaction, Trip } from "../model/flow.ts";
import {
  SEVERITY_LABEL,
  type Step,
  type StepState,
  type Verdict,
  friendlyDuration,
  friendlyModel,
} from "../model/story.ts";

const STATE_LABEL: Record<StepState, string> = {
  pending: "Pendiente",
  running: "En curso",
  ok: "Sin problemas",
  warn: "Con observaciones",
  bad: "Encontró un problema grave",
  skipped: "No se ejecutó",
  failed: "Falló",
  unknown: "Sin datos",
};

/** The steps of one run, top to bottom. */
export function StepList({ steps, snap }: { steps: Step[]; snap: Snapshot }) {
  return (
    <ol className="steps" aria-label="Pasos del análisis">
      {steps.map((step, i) => (
        <StepItem key={step.id} step={step} n={i + 1} snap={snap} />
      ))}
    </ol>
  );
}

/** What the run found, worst first, with how to fix each. */
export function Findings({ findings, snap }: { findings: Finding[]; snap: Snapshot }) {
  if (findings.length === 0) return null;
  return (
    <section className="findings" aria-labelledby="findings-title">
      <h2 id="findings-title">Qué habría que arreglar</h2>
      <ul>
        {findings.map((f, i) => (
          <FindingItem key={i} finding={f} snap={snap} />
        ))}
      </ul>
    </section>
  );
}

export function Seal({ verdict, progress }: { verdict: Verdict; progress: string }) {
  const score = verdict.safety;
  const r = 52;
  const c = 2 * Math.PI * r;
  return (
    <div className={`seal seal-${verdict.state}`} role="status" aria-live="polite">
      <svg viewBox="0 0 120 120" className="seal-ring" aria-hidden="true">
        <circle cx="60" cy="60" r={r} className="seal-track" />
        {score !== undefined && score > 0 && (
          <circle cx="60" cy="60" r={r} className="seal-fill" strokeDasharray={`${(score / 100) * c} ${c}`} />
        )}
        {verdict.state === "running" && <circle cx="60" cy="60" r={r} className="seal-spin" strokeDasharray={`${c * 0.18} ${c}`} />}
      </svg>
      <div className="seal-center">
        {score !== undefined ? (
          <>
            <span className="seal-score">{score}</span>
            <span className="seal-of">de 100</span>
          </>
        ) : (
          <span className="seal-progress">{verdict.state === "running" ? progress : "—"}</span>
        )}
      </div>
      <p className="seal-label">{verdict.label}</p>
      {verdict.reliability !== undefined && <p className="seal-sub">Robustez {verdict.reliability} de 100</p>}
    </div>
  );
}

function StepItem({ step, n, snap }: { step: Step; n: number; snap: Snapshot }) {
  const duration = friendlyDuration(step.durationMs);
  return (
    <li className={`step step-${step.state}`} aria-current={step.state === "running" ? "step" : undefined}>
      <span className="step-n" aria-hidden="true">
        {n}
      </span>
      <div className="step-card">
        <header className="step-head">
          <h2>{step.title}</h2>
          <p className="step-actor">{step.actor}</p>
          <p className="step-state">
            {STATE_LABEL[step.state]}
            {duration ? <span className="step-time">, {duration}</span> : null}
          </p>
        </header>

        {step.state !== "skipped" && <p className="step-what">{step.what}</p>}

        {step.facts.length > 0 && (
          <ul className="facts">
            {step.facts.map((f) => (
              <li key={f.label}>
                <span className="fact-v">{f.value}</span>
                <span className="fact-l">{f.label}</span>
              </li>
            ))}
          </ul>
        )}

        {step.conclusion && (
          <p className="step-conclusion">
            <strong>Conclusión.</strong> {step.conclusion}
          </p>
        )}

        {step.evidence?.map((e) => (
          <figure className="evidence" key={e.label}>
            <figcaption>{e.label}</figcaption>
            <pre>{e.text}</pre>
          </figure>
        ))}

        {(step.trip || step.technical.length > 0) && step.state !== "pending" && (
          <details className="tech">
            <summary>Ver el detalle técnico</summary>
            {step.trip && <TripPath trip={step.trip} snap={snap} />}
            <dl className="tech-rows">
              {step.technical.map((row) => (
                <div key={row.label} className={row.value.includes("\n") ? "tech-block" : undefined}>
                  <dt>{row.label}</dt>
                  <dd>{row.value.includes("\n") ? <pre>{row.value}</pre> : <code>{row.value}</code>}</dd>
                </div>
              ))}
            </dl>
          </details>
        )}
      </div>
    </li>
  );
}

/** The path one model call takes out of the sandbox and back. */
function TripPath({ trip, snap }: { trip: Trip; snap: Snapshot }) {
  const redactions: Redaction[] = trip.extras?.redactions ?? [];
  const masked = redactions.reduce((n, r) => n + r.count, 0);
  const gateway = !trip.extras && snap.gateway ? snap.gateway.redactions.reduce((n, r) => n + r.count, 0) : null;
  const done = trip.status !== "running";
  const lat = trip.extras?.latencyMs ?? {};
  const hops: { name: string; did: string; ms?: number }[] = [
    { name: "El agente", did: "arma la consulta con lo que juntó del servidor" },
    {
      name: "Occludra",
      did:
        masked > 0
          ? `tapó ${masked} ${masked === 1 ? "dato sensible" : "datos sensibles"} (${redactions.map((r) => r.detector).join(", ")})`
          : gateway !== null
            ? `tapa datos sensibles (${gateway} en total en la última hora, de todos los runs)`
            : trip.extras
              ? "no encontró datos sensibles para tapar"
              : "tapa emails, tokens y contraseñas",
      ms: lat.occludra,
    },
    { name: "NetBird", did: "lleva la consulta cifrada fuera de la caja aislada", ms: lat.netbird },
    { name: friendlyModel(trip.model), did: done ? "respondió" : "pensando…", ms: lat.llm },
    {
      name: "Respuesta",
      did: trip.status === "failed" ? "no llegó a tiempo" : done ? "vuelve en JSON y se guarda en el run" : "esperando",
    },
  ];
  return (
    <div className="trip">
      <p className="trip-title">Camino de la consulta al modelo</p>
      <ol className="trip-hops">
        {hops.map((h) => (
          <li key={h.name}>
            <span className="hop-name">{h.name}</span>
            <span className="hop-did">{h.did}</span>
            {h.ms !== undefined && <span className="hop-ms">{friendlyDuration(h.ms)}</span>}
          </li>
        ))}
      </ol>
      {redactions.some((r) => r.examples?.length) && (
        <p className="trip-note">
          Así lo vio el modelo: {redactions.flatMap((r) => r.examples ?? []).slice(0, 3).join(", ")}. Los ejemplos son de la
          demo; en el cluster Occludra solo cuenta, nunca guarda el contenido.
        </p>
      )}
    </div>
  );
}

function FindingItem({ finding, snap }: { finding: Finding; snap: Snapshot }) {
  const who = agentName(finding.agent, snap);
  return (
    <li className={`finding sev-${finding.severity.toLowerCase()}`}>
      <span className="sev">{SEVERITY_LABEL[finding.severity]}</span>
      <div>
        <h3>{finding.title}</h3>
        {finding.description && <p>{finding.description}</p>}
        {finding.remediation && (
          <p className="fix">
            <strong>Cómo se arregla:</strong> {finding.remediation}
          </p>
        )}
        <p className="who">Lo encontró {who}</p>
      </div>
    </li>
  );
}

function agentName(name: string, snap: Snapshot): string {
  if (name === "vigil-llm") return "Vigil";
  const role = snap.agents[name]?.spec.role;
  switch (role) {
    case "StaticSecurityAuditor":
      return "el auditor estático";
    case "DynamicProtocolFuzzer":
      return "el fuzzer de protocolo";
    case "RogueBehaviorProbe":
      return "la sonda de comportamiento";
    case "SynthesisScorer":
      return "la síntesis";
    default:
      return name;
  }
}
