'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { startApp, closeAll, request, signup, login, me, cookieOf, tokenOf, GOOD_PASSWORD, MINUTE } = require('./helpers');

async function loggedIn(app) {
  await signup(app);
  const res = await login(app);
  assert.equal(res.status, 200);
  return res;
}

describe('2. Secure cookies, logout and session expiry', () => {
  afterEach(closeAll);

  it('sets a hardened session cookie on login', async () => {
    const app = await startApp();
    const res = await loggedIn(app);
    assert.equal(res.setCookie.length, 1);

    const [pair, ...attrs] = res.setCookie[0].split('; ');
    assert.match(pair, /^__Host-sid=[A-Za-z0-9_-]{43}$/, '256-bit random token with __Host- prefix');
    for (const required of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=900']) {
      assert.ok(attrs.includes(required), `cookie should include ${required}, got: ${attrs.join('; ')}`);
    }
    assert.ok(!attrs.some((a) => /^Domain=/i.test(a)), 'no Domain attribute (host-only cookie)');
  });

  it('can drop Secure and the __Host- prefix only when explicitly configured for local HTTP', async () => {
    const app = await startApp({ secureCookies: false });
    const res = await loggedIn(app);
    assert.match(res.setCookie[0], /^sid=/);
    assert.ok(!res.setCookie[0].includes('Secure'));
    assert.ok(res.setCookie[0].includes('HttpOnly'));
  });

  it('does not keep the raw session token on the server', async () => {
    const app = await startApp();
    const token = tokenOf(await loggedIn(app));
    assert.equal(app.sessions.size, 1);
    for (const key of app.sessions.keys()) {
      assert.notEqual(key, token);
      assert.match(key, /^[0-9a-f]{64}$/, 'only a SHA-256 digest is stored');
    }
  });

  it('protects /me: no cookie, garbage cookie and unknown token all get 401', async () => {
    const app = await startApp();
    await loggedIn(app);
    for (const cookie of [null, '__Host-sid=garbage', `__Host-sid=${'A'.repeat(43)}`, '__Host-sid=']) {
      const res = await me(app, cookie);
      assert.equal(res.status, 401, `cookie ${cookie}`);
      assert.deepEqual(res.json, { error: 'Authentication required' });
    }
  });

  it('serves /me for a valid session', async () => {
    const app = await startApp();
    const cookie = cookieOf(await loggedIn(app));
    const res = await me(app, cookie);
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { email: 'alice@example.com' });
  });

  it('logout destroys the server-side session and clears the cookie', async () => {
    const app = await startApp();
    const cookie = cookieOf(await loggedIn(app));
    assert.equal((await me(app, cookie)).status, 200);

    const out = await request(app, { method: 'POST', path: '/logout', headers: { Cookie: cookie } });
    assert.equal(out.status, 200);
    assert.ok(out.setCookie[0].includes('Max-Age=0'), 'browser is told to delete the cookie');
    assert.equal(app.sessions.size, 0);

    // A stolen or replayed copy of the old cookie no longer works.
    assert.equal((await me(app, cookie)).status, 401);
  });

  it('logout without a session is harmless', async () => {
    const app = await startApp();
    const out = await request(app, { method: 'POST', path: '/logout' });
    assert.equal(out.status, 200);
  });

  it('expires idle sessions but keeps active ones alive', async () => {
    const app = await startApp();
    const cookie = cookieOf(await loggedIn(app));

    app.clock.t += 14 * MINUTE;
    assert.equal((await me(app, cookie)).status, 200, 'still valid after 14 idle minutes');
    app.clock.t += 14 * MINUTE; // 28 minutes since login, but only 14 since last use
    assert.equal((await me(app, cookie)).status, 200, 'activity extended the session');
    app.clock.t += 16 * MINUTE; // longer than the 15 minute idle limit
    const expired = await me(app, cookie);
    assert.equal(expired.status, 401);
    assert.ok(expired.setCookie[0].includes('Max-Age=0'), 'stale cookie is cleared');
    assert.equal(app.sessions.size, 0);
  });

  it('enforces an absolute lifetime even for constantly active sessions', async () => {
    const app = await startApp();
    const cookie = cookieOf(await loggedIn(app));

    for (let minutes = 10; minutes <= 470; minutes += 10) {
      app.clock.t += 10 * MINUTE;
      assert.equal((await me(app, cookie)).status, 200, `active at ${minutes} minutes`);
    }
    app.clock.t += 11 * MINUTE; // 481 minutes after login, only 11 minutes idle
    assert.equal((await me(app, cookie)).status, 401, 'absolute 8 hour limit reached');
  });

  it('issues a fresh session id on every login and retires the old one', async () => {
    const app = await startApp();
    const first = await loggedIn(app);
    const firstCookie = cookieOf(first);

    // Logging in again while presenting the old cookie must not reuse its id.
    const second = await request(app, {
      method: 'POST',
      path: '/login',
      body: { email: 'alice@example.com', password: GOOD_PASSWORD },
      headers: { Cookie: firstCookie },
    });
    assert.equal(second.status, 200);
    assert.notEqual(tokenOf(second), tokenOf(first));
    assert.equal((await me(app, firstCookie)).status, 401, 'old session id is dead');
    assert.equal((await me(app, cookieOf(second))).status, 200);
  });

  it('refuses cross-site state-changing requests (CSRF defence in depth)', async () => {
    const app = await startApp();
    const cookie = cookieOf(await loggedIn(app));

    const evilOrigin = await request(app, { method: 'POST', path: '/logout', headers: { Cookie: cookie, Origin: 'https://evil.example' } });
    assert.equal(evilOrigin.status, 403);
    const nullOrigin = await request(app, { method: 'POST', path: '/logout', headers: { Cookie: cookie, Origin: 'null' } });
    assert.equal(nullOrigin.status, 403);
    const crossSite = await request(app, { method: 'POST', path: '/logout', headers: { Cookie: cookie, 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(crossSite.status, 403);
    assert.equal((await me(app, cookie)).status, 200, 'session survived the forged requests');

    const evilLogin = await login(app, 'alice@example.com', GOOD_PASSWORD, { Origin: 'https://evil.example' });
    assert.equal(evilLogin.status, 403);
    assert.equal(evilLogin.setCookie.length, 0);

    const sameOrigin = await request(app, {
      method: 'POST',
      path: '/logout',
      headers: { Cookie: cookie, Origin: `http://127.0.0.1:${app.port}`, 'Sec-Fetch-Site': 'same-origin' },
    });
    assert.equal(sameOrigin.status, 200);
  });
});
