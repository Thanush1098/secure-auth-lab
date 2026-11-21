'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { startApp, closeAll, request, signup, login, GOOD_PASSWORD } = require('./helpers');

describe('1. Server-side input validation', () => {
  afterEach(closeAll);

  it('rejects weak passwords with 400 and does not create the account', async () => {
    const app = await startApp();
    const weak = [
      ['short', 'alice@example.com'],
      ['password1234', 'alice@example.com'],
      ['aaaaaaaaaaaaaaaa', 'alice@example.com'],
      ['alice-smith-2024', 'alice-smith@example.com'], // contains the email name
      ['ab'.repeat(65), 'alice@example.com'], // 130 chars: too long
    ];
    for (const [password, email] of weak) {
      const res = await signup(app, email, password);
      assert.equal(res.status, 400, `password ${password.slice(0, 20)} should be rejected`);
      assert.ok(Array.isArray(res.json.details) && res.json.details.length > 0);
    }
    assert.equal(app.users.size, 0);
  });

  it('rejects invalid email addresses', async () => {
    const app = await startApp();
    const invalid = ['not-an-email', 'a@b', '', '   ', 'a b@example.com', `${'x'.repeat(300)}@example.com`, 'two@@example.com'];
    for (const email of invalid) {
      const res = await signup(app, email);
      assert.equal(res.status, 400, `email ${email.slice(0, 20)} should be rejected`);
    }
    assert.equal(app.users.size, 0);
  });

  it('rejects wrong data types (type confusion / injection-shaped values)', async () => {
    const app = await startApp();
    const bodies = [
      { email: { $ne: null }, password: GOOD_PASSWORD },
      { email: ['alice@example.com'], password: GOOD_PASSWORD },
      { email: 'alice@example.com', password: 123456789012 },
      { email: 'alice@example.com', password: { $gt: '' } },
      { email: 'alice@example.com' },
      {},
    ];
    for (const body of bodies) {
      const res = await request(app, { method: 'POST', path: '/signup', body });
      assert.equal(res.status, 400, JSON.stringify(body));
    }
    const res = await request(app, { method: 'POST', path: '/login', body: { email: { $ne: null }, password: { $ne: null } } });
    assert.equal(res.status, 400);
    assert.equal(app.users.size, 0);
  });

  it('rejects malformed JSON, non-object JSON and wrong content types', async () => {
    const app = await startApp();
    const post = (extra) => request(app, { method: 'POST', path: '/signup', ...extra });

    assert.equal((await post({ rawBody: '{not json' })).status, 400);
    assert.equal((await post({ rawBody: '[1,2,3]' })).status, 400);
    assert.equal((await post({ rawBody: 'null' })).status, 400);
    assert.equal((await post({ rawBody: '"just a string"' })).status, 400);
    const wrongType = await post({ rawBody: 'email=a@b.com', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    assert.equal(wrongType.status, 415);
  });

  it('rejects oversized request bodies (declared and streamed)', async () => {
    const app = await startApp();
    const huge = JSON.stringify({ email: 'alice@example.com', password: 'x'.repeat(11 * 1024) });

    const declared = await request(app, { method: 'POST', path: '/signup', rawBody: huge });
    assert.equal(declared.status, 413);

    const streamed = await request(app, { method: 'POST', path: '/signup', rawBody: huge, chunked: true });
    assert.equal(streamed.status, 413);
    assert.equal(app.users.size, 0);
  });

  it('normalizes email addresses and blocks case-variant duplicates', async () => {
    const app = await startApp();
    assert.equal((await signup(app, '  Alice@Example.COM ')).status, 201);
    assert.ok(app.users.has('alice@example.com'));

    const duplicate = await signup(app, 'ALICE@example.com');
    assert.equal(duplicate.status, 400);
    assert.equal(duplicate.json.error, 'Unable to create account with those details');
    assert.equal(app.users.size, 1);

    assert.equal((await login(app, 'alice@EXAMPLE.com')).status, 200);
  });

  it('ignores prototype-pollution style keys in the body', async () => {
    const app = await startApp();
    const raw = `{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"email":"alice@example.com","password":"${GOOD_PASSWORD}"}`;
    const res = await request(app, { method: 'POST', path: '/signup', rawBody: raw });
    assert.equal(res.status, 201);
    assert.equal({}.polluted, undefined);
  });
});
