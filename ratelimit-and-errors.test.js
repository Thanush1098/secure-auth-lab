'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { startApp, closeAll, request, signup, login, me, cookieOf, tokenOf, GOOD_PASSWORD, MINUTE } = require('./helpers');

const GENERIC = { error: 'Invalid email or password' };

describe('3. Rate limits', () => {
  afterEach(closeAll);

  it('blocks the 6th login attempt after 5 failures, even with the right password, then recovers', async () => {
    const app = await startApp();
    await signup(app);
    for (let i = 0; i < 5; i += 1) {
      assert.equal((await login(app, 'alice@example.com', `wrong-password-${i}`)).status, 401);
    }
    const blocked = await login(app, 'alice@example.com', GOOD_PASSWORD);
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers['retry-after']) > 0 && Number(blocked.headers['retry-after']) <= 900);
    assert.equal(blocked.setCookie.length, 0, 'no session is issued while blocked');

    app.clock.t += 15 * MINUTE + 1000;
    assert.equal((await login(app)).status, 200, 'allowed again once the window passes');
  });

  it('resets the failure counter after a successful login', async () => {
    const app = await startApp();
    await signup(app);
    for (let i = 0; i < 4; i += 1) await login(app, 'alice@example.com', `wrong-password-${i}`);
    assert.equal((await login(app)).status, 200);

    for (let i = 0; i < 5; i += 1) {
      assert.equal((await login(app, 'alice@example.com', `again-wrong-${i}`)).status, 401);
    }
    assert.equal((await login(app, 'alice@example.com', 'one-more-wrong')).status, 429);
  });

  it('does not let one address lock the real owner out from another address', async () => {
    const app = await startApp({ trustProxy: true });
    await signup(app, 'alice@example.com', GOOD_PASSWORD, { 'X-Forwarded-For': '198.51.100.7' });
    const attacker = { 'X-Forwarded-For': '203.0.113.9' };
    const owner = { 'X-Forwarded-For': '198.51.100.7' };

    for (let i = 0; i < 5; i += 1) await login(app, 'alice@example.com', `guess-${i}-guess`, attacker);
    assert.equal((await login(app, 'alice@example.com', 'guess-again-xx', attacker)).status, 429);
    assert.equal((await login(app, 'alice@example.com', GOOD_PASSWORD, owner)).status, 200);
  });

  it('blocks an address that sprays guesses across many accounts', async () => {
    const app = await startApp({ trustProxy: true });
    const attacker = { 'X-Forwarded-For': '203.0.113.10' };
    for (let i = 0; i < 20; i += 1) {
      assert.equal((await login(app, `victim${i}@example.com`, 'spray-password-1', attacker)).status, 401);
    }
    const next = await login(app, 'victim-new@example.com', 'spray-password-1', attacker);
    assert.equal(next.status, 429);
  });

  it('limits sign-ups per address per hour', async () => {
    const app = await startApp();
    for (let i = 0; i < 10; i += 1) {
      assert.equal((await signup(app, `user${i}@example.com`)).status, 201);
    }
    const blocked = await signup(app, 'user10@example.com');
    assert.equal(blocked.status, 429);
    assert.ok(blocked.headers['retry-after']);
    assert.equal(app.users.size, 10);

    app.clock.t += 61 * MINUTE;
    assert.equal((await signup(app, 'user10@example.com')).status, 201);
  });

  it('applies an overall request budget per address', async () => {
    const app = await startApp({ limits: { requestsPerIpPerMinute: 5 } });
    for (let i = 0; i < 5; i += 1) {
      assert.equal((await request(app, { path: '/health' })).status, 200);
    }
    assert.equal((await request(app, { path: '/health' })).status, 429);
    app.clock.t += 61 * 1000;
    assert.equal((await request(app, { path: '/health' })).status, 200);
  });
});

describe('3. Generic authentication errors', () => {
  afterEach(closeAll);

  it('gives the same response for an unknown email and a wrong password', async () => {
    const app = await startApp();
    await signup(app);
    const wrongPassword = await login(app, 'alice@example.com', 'definitely-not-it');
    const unknownEmail = await login(app, 'nobody@example.com', 'definitely-not-it');

    assert.equal(wrongPassword.status, 401);
    assert.equal(unknownEmail.status, 401);
    assert.deepEqual(wrongPassword.json, GENERIC);
    assert.equal(wrongPassword.text, unknownEmail.text, 'identical bodies');
    assert.equal(wrongPassword.setCookie.length + unknownEmail.setCookie.length, 0);
  });

  it('treats very long or odd login passwords as ordinary failures', async () => {
    const app = await startApp();
    await signup(app);
    for (const password of ['x'.repeat(5000), '\u0000\u0000', ' ']) {
      const res = await login(app, 'alice@example.com', password);
      assert.equal(res.status, 401);
      assert.deepEqual(res.json, GENERIC);
    }
  });

  it('does not reveal internals when something unexpected breaks', async () => {
    // N=1000 is not a power of two, so scrypt throws inside the sign-up handler.
    const app = await startApp({ hashParams: { N: 1000, r: 8, p: 1 } });
    const res = await signup(app);
    assert.equal(res.status, 500);
    assert.deepEqual(res.json, { error: 'Internal server error' });
    assert.ok(!/scrypt|stack|at .*\.js|node:|ERR_/i.test(res.text), 'no internals in the response body');
    assert.ok(app.logs.some((l) => l.event === 'internal_error'), 'details are logged server-side instead');
  });

  it('uses plain generic messages for unknown routes and wrong methods', async () => {
    const app = await startApp();
    const missing = await request(app, { path: '/admin' });
    assert.equal(missing.status, 404);
    assert.deepEqual(missing.json, { error: 'Not found' });

    const wrongMethod = await request(app, { path: '/login' });
    assert.equal(wrongMethod.status, 405);
    assert.equal(wrongMethod.headers.allow, 'POST');

    const proto = await request(app, { path: '/__proto__' });
    assert.equal(proto.status, 404);
  });

  it('sends defensive security headers on every response', async () => {
    const app = await startApp();
    const res = await request(app, { path: '/health' });
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.match(res.headers['content-security-policy'], /default-src 'none'/);
    assert.match(res.headers['strict-transport-security'], /max-age=/);
    assert.equal(res.headers['x-powered-by'], undefined);
  });

  it('never writes passwords, session tokens or raw emails to the logs', async () => {
    const app = await startApp();
    await signup(app);
    await login(app, 'alice@example.com', 'wrong-password-xx');
    const ok = await login(app);
    const token = tokenOf(ok);
    await request(app, { method: 'POST', path: '/logout', headers: { Cookie: cookieOf(ok) } });
    await me(app, cookieOf(ok));

    const dump = JSON.stringify(app.logs);
    assert.ok(app.logs.length >= 4, 'auth events are being logged');
    assert.ok(!dump.includes(GOOD_PASSWORD));
    assert.ok(!dump.includes('wrong-password-xx'));
    assert.ok(!dump.includes(token));
    assert.ok(!dump.includes('alice@example.com'));
    const events = app.logs.map((l) => l.event);
    for (const expected of ['signup', 'login_failure', 'login_success', 'logout']) {
      assert.ok(events.includes(expected), `logs include ${expected}`);
    }
  });
});
