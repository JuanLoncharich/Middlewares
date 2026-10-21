import assert from 'node:assert/strict';
import test from 'node:test';
import { customModelLimit } from '../dist/providers.js';
import { assertOpenCodeAgent } from '../dist/types.js';

const agent = (model) => ({
  apiVersion: 'security.eval.io/v1alpha1',
  kind: 'OpenCodeAgent',
  metadata: { name: 'a' },
  spec: {
    role: 'static-auditor',
    model,
    systemPrompt: 'x',
    outputFormat: { type: 'json_schema', schema: {} },
  },
});

test('custom providers default to 128K context and 8K output', () => {
  assert.deepEqual(customModelLimit(), { context: 128000, output: 8192 });
});

test('a served window is declared as is, output capped at a quarter', () => {
  assert.deepEqual(customModelLimit(32768), { context: 32768, output: 8192 });
  assert.deepEqual(customModelLimit(8192), { context: 8192, output: 2048 });
});

test('spec.model.contextTokens is read and validated', () => {
  assert.equal(assertOpenCodeAgent(agent({ providerID: 'local', modelID: 'm', contextTokens: 32768 })).spec.model.contextTokens, 32768);
  assert.equal(assertOpenCodeAgent(agent({ providerID: 'local', modelID: 'm' })).spec.model.contextTokens, undefined);
  assert.throws(() => assertOpenCodeAgent(agent({ providerID: 'local', modelID: 'm', contextTokens: 100 })), /contextTokens/);
  assert.throws(() => assertOpenCodeAgent(agent({ providerID: 'local', modelID: 'm', contextTokens: '32k' })), /contextTokens/);
});
