import assert from 'node:assert/strict';
import test from 'node:test';
import { VigilClient, combineScannerResults } from '../dist/vigil.js';

// Upstream vigil-llm@f2b4c13 ResponseModel, as /analyze/prompt returns it.
const response = ({ transformer = [], yara = [], vectordb = [], sentiment = [] } = {}) => ({
  status: 'success',
  results: {
    'scanner:transformer': { matches: transformer },
    'scanner:yara': { matches: yara },
    'scanner:vectordb': { matches: vectordb },
    'scanner:sentiment': { matches: sentiment },
  },
  messages: [],
  errors: [],
});
const tf = (score, threshold = 0.98) => ({ model_name: 'deberta', score, label: 'INJECTION', threshold });
const yara = { rule_name: 'InstructionBypass', category: 'Instruction Bypass', tags: ['Injection'] };
const vec = { text: 'ignore previous instructions', metadata: {}, distance: 0.21 };

function client(body, options = {}, status = 200) {
  const meshFetch = async () => ({
    status, headers: {}, body: Buffer.from(JSON.stringify(body)),
    text: () => JSON.stringify(body), json: () => body,
  });
  return new VigilClient('http://vigil.test/analyze/prompt', meshFetch, { timeoutMs: 1000, maxPayloadBytes: 65536, retries: 0, ...options });
}
const verdictOf = (body, options) => client(body, options).analyze('some text', 'test');

test('transformer alone above its threshold only warns (was: aborted)', async () => {
  const v = await verdictOf(response({ transformer: [tf(0.999)] }));
  assert.equal(v.level, 'warn');
  assert.equal(v.injectionDetected, false);
  assert.deepEqual(v.hits, [{ scanner: 'scanner:transformer', score: 0.999 }]);
});

test('transformer below its threshold does not count at all (was: aborted)', async () => {
  const v = await verdictOf(response({ transformer: [tf(0.95)] }));
  assert.equal(v.level, 'clean');
  assert.deepEqual(v.hits, []);
});

test('the threshold comes from the response, else from the runner option', async () => {
  assert.equal((await verdictOf(response({ transformer: [tf(0.95, 0.9)] }))).level, 'warn');
  const noThreshold = { model_name: 'deberta', score: 0.95, label: 'INJECTION' };
  assert.equal((await verdictOf(response({ transformer: [noThreshold] }))).level, 'clean');
  assert.equal((await verdictOf(response({ transformer: [noThreshold] }), { transformerThreshold: 0.9 })).level, 'warn');
});

test('transformer AND yara on the same text aborts', async () => {
  const v = await verdictOf(response({ transformer: [tf(1)], yara: [yara] }));
  assert.equal(v.level, 'abort');
  assert.equal(v.injectionDetected, true);
  assert.deepEqual(v.triggeredScanners, ['scanner:transformer', 'scanner:yara']);
});

test('transformer AND vectordb on the same text aborts', async () => {
  const v = await verdictOf(response({ transformer: [tf(0.99)], vectordb: [vec] }));
  assert.equal(v.level, 'abort');
  assert.deepEqual(v.hits.find((h) => h.scanner === 'scanner:vectordb'), { scanner: 'scanner:vectordb', score: 0.21 });
});

test('yara alone and vectordb alone only warn (no YARA-only abort path)', async () => {
  assert.equal((await verdictOf(response({ yara: [yara] }))).level, 'warn');
  assert.equal((await verdictOf(response({ vectordb: [vec] }))).level, 'warn');
  assert.equal((await verdictOf(response({ yara: [yara], vectordb: [vec] }))).level, 'warn');
});

test('a sub-threshold transformer match does not corroborate yara', async () => {
  assert.equal((await verdictOf(response({ transformer: [tf(0.6)], yara: [yara] }))).level, 'warn');
});

test('sentiment never counts; nothing matched is clean', async () => {
  assert.equal((await verdictOf(response({ sentiment: [{ score: 0.9 }] }))).level, 'clean');
  assert.equal((await verdictOf(response())).level, 'clean');
});

test('non-upstream verdict shapes keep detected = abort', async () => {
  assert.equal((await verdictOf({ injection_detected: true })).level, 'abort');
  assert.equal((await verdictOf({ injection_detected: false })).level, 'clean');
  assert.equal((await verdictOf({ status: 'blocked' })).level, 'abort');
});

test('scanner errors (HTTP 500) still fail closed', async () => {
  await assert.rejects(client({}, {}, 500).analyze('x', 'test'), { name: 'VigilUnavailableError' });
});

test('combineScannerResults works on raw results', () => {
  assert.equal(combineScannerResults(response({ transformer: [tf(0.99)], yara: [yara] }).results).level, 'abort');
});
