import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { CANARY_LINES, createHandler, PROBE_TIMEOUT_MS, PROBE_URL } from '../server.mjs';

const auth = { 'x-auth-oid': 'synthetic-test-identity', accept: 'application/json' };
const hash = (value) => createHash('sha256').update(value).digest('hex');
async function call(handler, { url = '/', method = 'GET', headers = auth } = {}) {
  const response = { status: null, headers: {}, body: '' };
  await handler({ url, method, headers }, {
    writeHead(status, responseHeaders) { response.status = status; response.headers = responseHeaders; },
    end(body) { response.body = body; },
  });
  if (response.headers['content-type'].startsWith('application/json')) response.data = JSON.parse(response.body);
  return response;
}

test('default runtime status is useful, secret-free, and source baked', async () => {
  const response = await call(createHandler({ env: {} }));
  assert.equal(response.status, 200);
  assert.deepEqual(response.data, { fixture: 'production-uat-core', sourceRevision: 'source-v2', release: 'env-v1', identityPresent: true, cliSecret: { present: false, matchesExpected: false }, uiSecret: { present: false, matchesExpected: false } });
  assert.equal(response.headers['cache-control'], 'no-store');
  assert(!response.body.includes(auth['x-auth-oid']));
});

test('runtime marker changes without a source rebuild', async () => {
  assert.equal((await call(createHandler({ env: { UAT_RELEASE: 'env-v2' } }))).data.release, 'env-v2');
});

test('secrets and expectations return only presence and equality booleans', async () => {
  const cli = 'synthetic-test-cli-value';
  const ui = 'synthetic-test-ui-value';
  const response = await call(createHandler({ env: { UAT_260929_CLI: cli, UAT_CLI_SHA256: hash(cli), UAT_260929_UI: ui, UAT_UI_SHA256: hash('different') } }));
  assert.deepEqual(response.data.cliSecret, { present: true, matchesExpected: true });
  assert.deepEqual(response.data.uiSecret, { present: true, matchesExpected: false });
  for (const value of [cli, ui, hash(cli), hash('different')]) assert(!response.body.includes(value));
});

test('malformed or missing expected hash safely gives false', async () => {
  for (const expected of [undefined, '', 'bad', 'f'.repeat(62)]) {
    const response = await call(createHandler({ env: { UAT_260929_CLI: 'synthetic', UAT_CLI_SHA256: expected } }));
    assert.deepEqual(response.data.cliSecret, { present: true, matchesExpected: false });
  }
});

test('HTML renders safe status for normal browser navigation', async () => {
  const response = await call(createHandler({ env: {} }), { headers: { 'x-auth-subject': 'synthetic-fallback' } });
  assert.equal(response.status, 200);
  assert.match(response.headers['content-type'], /text\/html/);
  assert.match(response.body, /source-v2/);
  assert.match(response.body, /id="result"/);
  assert(!response.body.includes('synthetic-fallback'));
});

test('invalid marker cannot inject HTML or reveal unexpected environment data', async () => {
  const response = await call(createHandler({ env: { UAT_RELEASE: '<script>alert(1)</script>' } }));
  assert.equal(response.data.release, 'invalid-marker');
  assert(!response.body.includes('<script>'));
});

test('missing identity denied, minimal health check stays available', async () => {
  for (const url of ['/', '/status', '/probe', '/log-canary']) {
    const response = await call(createHandler({ env: {} }), { url, headers: { accept: 'application/json' } });
    assert.equal(response.status, 401);
    assert.deepEqual(response.data, { error: 'unauthenticated', identityPresent: false });
  }
  const response = await call(createHandler({ env: {} }), { url: '/healthz', headers: {} });
  assert.equal(response.status, 200);
  assert.equal(response.body, 'ok\n');
});

test('probe makes one bounded fixed HTTPS request, without forwarding headers', async () => {
  let count = 0;
  let cancelled = false;
  const handler = createHandler({ env: {}, fetchImpl: async (url, options) => {
    count++;
    assert.equal(url, 'https://example.com/');
    assert.equal(url, PROBE_URL);
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers, undefined);
    assert(options.signal instanceof AbortSignal);
    return { ok: true, status: 200, body: { async cancel() { cancelled = true; } } };
  } });
  await call(handler);
  assert.equal(count, 0);
  const response = await call(handler, { url: '/probe' });
  assert.equal(count, 1);
  assert(cancelled);
  assert.equal(PROBE_TIMEOUT_MS, 10000);
  assert.deepEqual(response.data.probe, { target: 'example.com:443', reachable: true, httpStatus: 200, outcome: 'success' });
});

test('probe errors are classified without printing internal errors', async () => {
  for (const name of ['TimeoutError', 'AbortError', 'TypeError']) {
    const response = await call(createHandler({ env: {}, fetchImpl: async () => { throw Object.assign(new Error('sensitive diagnostic must not be rendered'), { name }); } }), { url: '/probe' });
    assert.equal(response.data.probe.reachable, false);
    assert.equal(response.data.probe.outcome, name === 'TypeError' ? 'network_error' : 'timeout');
    assert(!response.body.includes('sensitive diagnostic'));
  }
});

test('concurrent probes are bounded to one request', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const handler = createHandler({ env: {}, fetchImpl: async () => { await pending; return { ok: true, status: 200 }; } });
  const first = call(handler, { url: '/probe' });
  assert.equal((await call(handler, { url: '/probe' })).status, 409);
  release();
  assert.equal((await first).status, 200);
});

test('probe accepts no arbitrary target, query, or alternate method', async () => {
  let fetched = false;
  const handler = createHandler({ env: {}, fetchImpl: async () => { fetched = true; } });
  for (const url of ['/probe?url=https://other.example', '/probe/other', '/?target=other']) assert.equal((await call(handler, { url })).status, 404);
  assert.equal((await call(handler, { url: '/probe', method: 'POST' })).status, 405);
  assert.equal(fetched, false);
});

test('log route writes fixed synthetic canaries once, never real headers or secrets', async () => {
  const logs = [];
  const handler = createHandler({ env: { UAT_260929_CLI: 'do-not-log-this' }, logger: (line) => logs.push(line) });
  const headers = { ...auth, authorization: 'Bearer not-a-canary', cookie: 'session=not-a-canary' };
  const first = await call(handler, { url: '/log-canary', headers });
  const again = await call(handler, { url: '/log-canary', headers });
  assert.equal(first.data.alreadyWritten, false);
  assert.equal(again.data.alreadyWritten, true);
  assert.deepEqual(logs, [...CANARY_LINES]);
  for (const value of ['not-a-canary', 'do-not-log-this', auth['x-auth-oid']]) assert(!JSON.stringify(logs).includes(value));
  assert(!first.body.includes('uat-260929-fixed-synthetic-auth'));
});

test('unknown routes give controlled errors and make no outgoing requests', async () => {
  let count = 0;
  const response = await call(createHandler({ env: {}, fetchImpl: async () => { count++; } }), { url: '/missing' });
  assert.equal(response.status, 404);
  assert.equal(count, 0);
});
