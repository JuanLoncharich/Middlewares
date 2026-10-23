import type { DemoSource } from "../data/demo/replay.ts";
import { SCENARIOS } from "../data/demo/scenarios.ts";
import type { ReplayState } from "../data/source.ts";

const SPEEDS = [1, 2, 4];

export function ReplayBar({ demo, replay }: { demo: DemoSource; replay: ReplayState }) {
  const pct = replay.durationMs > 0 ? (replay.elapsedMs / replay.durationMs) * 100 : 0;
  const done = replay.elapsedMs >= replay.durationMs;
  const current = SCENARIOS.find((s) => s.id === replay.scenario);
  return (
    <div className="replay" role="group" aria-label="Controles de la demo">
      <div className="replay-scenarios" role="radiogroup" aria-label="Escenario">
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            type="button"
            role="radio"
            aria-checked={s.id === replay.scenario}
            className={`chip ${s.id === replay.scenario ? "chip-on" : ""}`}
            onClick={() => demo.setScenario(s.id)}
            title={s.blurb}
          >
            {s.label}
          </button>
        ))}
      </div>
      <p className="replay-blurb">{current?.blurb}</p>
      <div className="replay-controls">
        <button type="button" className="button" onClick={() => (done ? demo.restart() : demo.setPlaying(!replay.playing))}>
          {done ? "Repetir" : replay.playing ? "Pausar" : "Reanudar"}
        </button>
        <div className="speeds" role="radiogroup" aria-label="Velocidad">
          {SPEEDS.map((sp) => (
            <button
              key={sp}
              type="button"
              role="radio"
              aria-checked={replay.speed === sp}
              className={`chip chip-small ${replay.speed === sp ? "chip-on" : ""}`}
              onClick={() => demo.setSpeed(sp)}
            >
              {sp}×
            </button>
          ))}
        </div>
        <div
          className="replay-track"
          role="progressbar"
          aria-label="Avance del escenario"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(pct)}
        >
          <span style={{ width: `${pct}%` }} />
        </div>
        <button type="button" className="button-quiet" onClick={() => demo.skipToEnd()} disabled={done}>
          Saltar al veredicto
        </button>
      </div>
    </div>
  );
}
