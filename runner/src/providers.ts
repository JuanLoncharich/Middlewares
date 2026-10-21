/** Model limits declared to OpenCode for custom (non-catalog) providers. */

const CUSTOM_MODEL_CONTEXT = 128_000;
const CUSTOM_MODEL_OUTPUT = 8_192;

/**
 * The served context window (spec.model.contextTokens, default 128K) and an
 * output budget of at most a quarter of it, so a small local window still
 * leaves room for the prompt.
 */
export function customModelLimit(contextTokens?: number): { context: number; output: number } {
  const context = contextTokens ?? CUSTOM_MODEL_CONTEXT;
  return { context, output: Math.min(CUSTOM_MODEL_OUTPUT, Math.floor(context / 4)) };
}
