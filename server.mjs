import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

export const SOURCE_REVISION = 'source-v2';
export const PROBE_URL = 'https://example.com/';
export const PROBE_TIMEOUT_MS = 3000;
export const CANARY_LINES = Object.freeze([
  'uat-260929-core-log-marker',
  'Authorization: Bearer uat-260929-fixed-synthetic-auth',
  'Cookie: uat_session=uat-260929-fixed-synthetic-cookie',
]);

function secretState(value, expectedHash) {
  const present = typeof value === 'string' && value.length > 0;
  const expectationValid = typeof expectedHash === 'string' && /^[a-f0-9]{64}$/i.test(expectedHash);
  const matchesExpected = present && expectationValid
    ? timingSafeEqual(createHash('sha256').update(value).digest(), Buffer.from(expectedHash, 'hex'))
    : false;
  return { present, matchesExpected };
}

function identityPresent(headers) {
  return Boolean(headers['x-auth-oid'] || headers['x-auth-subject']);
}

function snapshot(env, headers) {
  const marker = env.UAT_RELEASE ?? 'env-v1';
  return {
    fixture: 'production-uat-core',
    sourceRevision: SOURCE_REVISION,
    release: /^[a-zA-Z0-9._-]{1,64}$/.test(marker) ? marker : 'invalid-marker',
    identityPresent: identityPresent(headers),
    cliSecret: secretState(env.UAT_260929_CLI, env.UAT_CLI_SHA256),
    uiSecret: secretState(env.UAT_260929_UI, env.UAT_UI_SHA256),
  };
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function respond(req, res, status, data) {
  const json = typeof req.headers.accept === 'string' && req.headers.accept.includes('application/json');
  res.writeHead(status, {
    'content-type': json ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  });
  const serialized = JSON.stringify(data, null, 2);
  if (json) { res.end(serialized); return; }
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Production UAT core</title><style>body{font:18px system-ui;max-width:850px;margin:40px auto;padding:0 20px;color:#152b40;background:#f7fafc}pre{white-space:pre-wrap;background:#fff;padding:20px;border:1px solid #c7d3df;border-radius:8px}nav a{display:inline-block;margin:0 20px 16px 0;color:#075ba6}</style></head><body><h1>Production UAT core</h1><nav><a href="/">Runtime</a><a href="/probe">Run one HTTPS probe</a><a href="/log-canary">Emit synthetic log canaries once</a></nav><pre id="result">${escapeHTML(serialized)}</pre><p>Only synthetic test data. No credentials or request-header values are displayed.</p></body></html>`);
}

export function createHandler({ env = process.env, fetchImpl = globalThis.fetch, logger = console.log } = {}) {
  let canaryWritten = false;
  let probeRunning = false;
  return async (req, res) => {
    if (req.url === '/healthz' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      res.end('ok\n');
      return;
    }
    if (!identityPresent(req.headers)) {
      respond(req, res, 401, { error: 'unauthenticated', identityPresent: false });
      return;
    }
    if (req.method !== 'GET') {
      respond(req, res, 405, { error: 'method_not_allowed' });
      return;
    }
    if (req.url === '/' || req.url === '/status') {
      respond(req, res, 200, snapshot(env, req.headers));
      return;
    }
    if (req.url === '/log-canary') {
      const alreadyWritten = canaryWritten;
      if (!canaryWritten) {
        canaryWritten = true;
        for (const line of CANARY_LINES) logger(line);
      }
      respond(req, res, 200, { ...snapshot(env, req.headers), logCanaryWritten: true, alreadyWritten });
      return;
    }
    if (req.url === '/probe') {
      if (probeRunning) { respond(req, res, 409, { error: 'probe_already_running' }); return; }
      probeRunning = true;
      let probe;
      try {
        const response = await fetchImpl(PROBE_URL, {
          method: 'GET',
          redirect: 'error',
          signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
        });
        await response.body?.cancel();
        probe = { target: 'example.com:443', reachable: true, httpStatus: response.status, outcome: response.ok ? 'success' : 'http_error' };
      } catch (error) {
        probe = { target: 'example.com:443', reachable: false, httpStatus: null, outcome: error?.name === 'TimeoutError' || error?.name === 'AbortError' ? 'timeout' : 'network_error' };
      } finally {
        probeRunning = false;
      }
      respond(req, res, 200, { ...snapshot(env, req.headers), probe });
      return;
    }
    respond(req, res, 404, { error: 'not_found' });
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  const server = createServer(createHandler());
  server.listen(port, '0.0.0.0', () => console.log('uat-260929-core-listening'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
}
