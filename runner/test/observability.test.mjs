import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { once } from 'node:events';
import { startTelemetry, stopTelemetry, evaluationTrace, inSpan, requestTraceHeaders } from '../dist/observability.js';
import { Logger } from '../dist/logger.js';

test('job telemetry preserves parent context, exports before exit, and excludes payloads', async () => {
  const received = [];
  const collector = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      received.push({ path: req.url, body: JSON.parse(Buffer.concat(chunks).toString()) });
      res.setHeader('content-type', 'application/json'); res.end('{}');
    });
  });
  collector.listen(0, '127.0.0.1'); await once(collector, 'listening');
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = `http://127.0.0.1:${collector.address().port}`;
  process.env.TRACEPARENT = '00-11111111111111111111111111111111-2222222222222222-01';
  process.env.RUN_NAME = 'telemetry-test'; process.env.RUN_NAMESPACE = 'mcp-evals';
  startTelemetry();
  try {
    await evaluationTrace(async () => {
      await inSpan('evaluation.agent', { 'mcp.agent.kind': 'static' }, async () => {
        assert.match(requestTraceHeaders().traceparent, /^00-11111111111111111111111111111111-/);
        assert.equal(requestTraceHeaders()['x-mcp-run'], 'telemetry-test');
      });
      return 1;
    });
    await stopTelemetry();
    const spans = received.filter(r => r.path === '/v1/traces').flatMap(r => r.body.resourceSpans.flatMap(rs => rs.scopeSpans.flatMap(ss => ss.spans)));
    assert.ok(spans.some(s => s.name === 'evaluation.agent'));
    assert.ok(spans.some(s => s.name === 'evaluation.execute' && s.status.code === 2));
    assert.ok(spans.every(s => s.traceId === '11111111111111111111111111111111'));
    assert.ok(received.some(r => r.path === '/v1/metrics'));
    assert.ok(!JSON.stringify(received).includes('prompt'));
  } finally { collector.close(); }
});

test('structured logs remove sensitive evidence and retain diagnostic context', () => {
  let line = '';
  const original = process.stderr.write;
  process.stderr.write = (chunk) => { line += chunk; return true; };
  try {
    new Logger('test').info('scan result', { excerpt: 'private evidence', nested: { authorization: 'Bearer secret', prompt: 'private prompt' }, email: 'user@example.com', error: new Error('failure') });
  } finally { process.stderr.write = original; }
  assert.ok(!line.includes('private evidence'));
  assert.ok(!line.includes('private prompt'));
  assert.ok(!line.includes('Bearer secret'));
  assert.ok(!line.includes('user@example.com'));
  const record = JSON.parse(line);
  assert.equal(record.run, 'telemetry-test');
  assert.equal(record.error.name, 'Error');
});

test('an unavailable collector cannot change the evaluation result or hang shutdown', async () => {
  const { spawnSync } = await import('node:child_process');
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { startTelemetry, stopTelemetry, evaluationTrace } from './dist/observability.js';
    startTelemetry();
    const code = await evaluationTrace(async () => 0);
    await stopTelemetry();
    console.log('evaluation-code=' + code);
  `], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:1' },
    encoding: 'utf8', timeout: 7000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /evaluation-code=0/);
});
