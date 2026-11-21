'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { hashPassword, verifyPassword, DEFAULT_PARAMS } = require('./password');
const { startApp, closeAll, signup, GOOD_PASSWORD } = require('./helpers');

describe('1. Password hashing', () => {
  afterEach(closeAll);

  it('uses salted scrypt and never contains the plaintext password', async () => {
    const first = await hashPassword(GOOD_PASSWORD);
    const second = await hashPassword(GOOD_PASSWORD);
    assert.match(first, /^scrypt\$32768\$8\$3\$/);
    assert.notEqual(first, second, 'same password must hash differently each time (random salt)');
    assert.ok(!first.includes(GOOD_PASSWORD));
  });

  it('accepts the right password and rejects wrong ones', async () => {
    const hash = await hashPassword(GOOD_PASSWORD);
    assert.equal(await verifyPassword(GOOD_PASSWORD, hash), true);
    assert.equal(await verifyPassword('correct horse battery stapler', hash), false);
    assert.equal(await verifyPassword('', hash), false);
  });

  it('treats canonically equivalent Unicode passwords as the same password', async () => {
    const hash = await hashPassword('café au lait 2024!');
    assert.equal(await verifyPassword('café au lait 2024!', hash), true);
  });

  it('fails closed on malformed or tampered stored hashes', async () => {
    const bad = [
      undefined,
      null,
      '',
      'plaintext-password',
      'scrypt$1$2$3$a',
      'md5$16384$8$1$AAAA$AAAA',
      'scrypt$999999999$8$1$AAAA$AAAA', // absurd memory cost
      'scrypt$abc$8$1$AAAA$AAAA',
    ];
    for (const stored of bad) {
      assert.equal(await verifyPassword(GOOD_PASSWORD, stored), false, `should reject ${String(stored)}`);
    }
  });

  it('stores only the hash in the account record', async () => {
    const app = await startApp();
    const res = await signup(app);
    assert.equal(res.status, 201);
    const record = app.users.get('alice@example.com');
    assert.match(record.passwordHash, /^scrypt\$/);
    assert.ok(!JSON.stringify([...app.users.values()]).includes(GOOD_PASSWORD));
  });

  it('uses the production cost parameters by default', async () => {
    const app = await startApp({ hashParams: undefined });
    await signup(app);
    const { N, r, p } = DEFAULT_PARAMS;
    const prefix = `scrypt$${N}$${r}$${p}$`;
    assert.ok(app.users.get('alice@example.com').passwordHash.startsWith(prefix));
  });
});
