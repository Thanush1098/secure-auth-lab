'use strict';

const crypto = require('node:crypto');

// scrypt cost parameters. N=2^15, r=8, p=3 is one of the equivalent
// configurations listed in the OWASP Password Storage Cheat Sheet.
// The parameters are stored inside every hash, so they can be raised later
// without breaking existing accounts.
const DEFAULT_PARAMS = Object.freeze({ N: 2 ** 15, r: 8, p: 3 });
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;

// Upper bounds applied to parameters read back from storage, so a tampered
// record cannot make the server allocate gigabytes of memory.
const MAX_STORED_N = 2 ** 17;
const MAX_STORED_R = 16;
const MAX_STORED_P = 16;
const MAX_MEMORY = 256 * 1024 * 1024;

function deriveKey(password, salt, { N, r, p }) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      // NFKC normalization so visually identical passwords hash the same way.
      password.normalize('NFKC'),
      salt,
      KEY_LENGTH,
      { N, r, p, maxmem: MAX_MEMORY },
      (err, key) => (err ? reject(err) : resolve(key)),
    );
  });
}

/**
 * Hash a password with a fresh random salt.
 * Format: scrypt$N$r$p$<salt base64>$<key base64>
 */
async function hashPassword(password, params = DEFAULT_PARAMS) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = await deriveKey(password, salt, params);
  return ['scrypt', params.N, params.r, params.p, salt.toString('base64'), key.toString('base64')].join('$');
}

/**
 * Check a password against a stored hash in constant time.
 * Anything malformed counts as "does not match" instead of throwing.
 */
async function verifyPassword(password, stored) {
  if (typeof password !== 'string' || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (![N, r, p].every(Number.isInteger)) return false;
  if (N < 2 || r < 1 || p < 1) return false;
  if (N > MAX_STORED_N || r > MAX_STORED_R || p > MAX_STORED_P) return false;

  try {
    const salt = Buffer.from(parts[4], 'base64');
    const expected = Buffer.from(parts[5], 'base64');
    if (salt.length === 0 || expected.length !== KEY_LENGTH) return false;
    const actual = await deriveKey(password, salt, { N, r, p });
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword, DEFAULT_PARAMS };
