'use strict';

// Shared test helpers. Not named like a test file, so the test runner does not run it on its own.

const http = require('node:http');
const { createApp } = require('./app');

const MINUTE = 60 * 1000;
const GOOD_PASSWORD = 'correct horse battery staple'; // fake, for tests only

// Cheap scrypt settings keep the suite fast. One test checks the real defaults.
const FAST_HASH = { N: 2 ** 10, r: 8, p: 1 };

const running = [];

/** Starts an app on a random local port with a controllable clock and captured logs. */
async function startApp(options = {}) {
  const clock = { t: 1_700_000_000_000 };
  const logs = [];
  const { server, users, sessions, config } = createApp({
    hashParams: FAST_HASH,
    now: () => clock.t,
    logger: (event, fields) => logs.push({ event, ...fields }),
    ...options,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const app = { server, users, sessions, config, clock, logs, port: server.address().port };
  running.push(app);
  return app;
}

async function closeAll() {
  while (running.length > 0) {
    const { server } = running.pop();
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
}

/** Minimal HTTP client. Returns status, headers, parsed JSON and Set-Cookie values. */
function request(app, { method = 'GET', path = '/', headers = {}, body, rawBody, chunked = false } = {}) {
  return new Promise((resolve, reject) => {
    let payload;
    if (rawBody !== undefined) payload = rawBody;
    else if (body !== undefined) payload = JSON.stringify(body);

    const finalHeaders = { ...headers };
    const hasType = Object.keys(finalHeaders).some((k) => k.toLowerCase() === 'content-type');
    if (payload !== undefined) {
      if (!hasType) finalHeaders['Content-Type'] = 'application/json';
      if (!chunked) finalHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      { host: '127.0.0.1', port: app.port, method, path, headers: finalHeaders, agent: false },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* not JSON */
          }
          resolve({ status: res.statusCode, headers: res.headers, text, json, setCookie: res.headers['set-cookie'] || [] });
        });
      },
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const signup = (app, email = 'alice@example.com', password = GOOD_PASSWORD, headers = {}) =>
  request(app, { method: 'POST', path: '/signup', body: { email, password }, headers });

const login = (app, email = 'alice@example.com', password = GOOD_PASSWORD, headers = {}) =>
  request(app, { method: 'POST', path: '/login', body: { email, password }, headers });

/** "name=value" part of the first Set-Cookie header, or null. */
const cookieOf = (res) => (res.setCookie.length > 0 ? res.setCookie[0].split(';')[0] : null);

/** Just the token value from the first Set-Cookie header. */
const tokenOf = (res) => cookieOf(res).split('=')[1];

const me = (app, cookie) =>
  request(app, { method: 'GET', path: '/me', headers: cookie ? { Cookie: cookie } : {} });

module.exports = { startApp, closeAll, request, signup, login, me, cookieOf, tokenOf, GOOD_PASSWORD, FAST_HASH, MINUTE };
