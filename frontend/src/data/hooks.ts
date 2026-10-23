import { useSyncExternalStore } from "react";
import type { DemoSource } from "./demo/replay.ts";
import type { DataSource, ReplayState, Snapshot } from "./source.ts";

export function useSnapshot(source: DataSource): Snapshot {
  return useSyncExternalStore(source.subscribe, source.getSnapshot);
}

const NO_REPLAY = (): ReplayState | null => null;
const NO_SUBSCRIBE = () => () => {};

export function useReplay(demo: DemoSource | null): ReplayState | null {
  return useSyncExternalStore(demo ? demo.subscribeReplay : NO_SUBSCRIBE, demo ? demo.getReplay : NO_REPLAY);
}
