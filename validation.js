'use strict';

const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;
const MAX_EMAIL_LENGTH = 254;
const MAX_EMAIL_LOCAL_LENGTH = 64;

// Practical email check (same shape as the HTML5 spec pattern, with bounded
// repetition so it cannot be used for regex denial of service).
const EMAIL_RE =
  /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

// A tiny deny-list for the lab. A real service should check against a large
// breached-password list (for example the Have I Been Pwned range API).
const COMMON_PASSWORDS = new Set([
  'password1234',
  'password12345',
  'password123456',
  '123456789012',
  '1234567890123',
  'qwertyuiop12',
  'qwertyuiop123',
  'letmein12345',
  'iloveyou1234',
  'administrator',
  'welcome12345',
  'changeme1234',
  'abcdefghijkl',
  'abc123abc123',
]);

/**
 * Returns a trimmed, lower-cased email or null when the value is not a valid
 * email string. Non-strings (objects, arrays, numbers) are always rejected.
 */
function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  if (email.length === 0 || email.length > MAX_EMAIL_LENGTH) return null;
  const at = email.lastIndexOf('@');
  if (at < 1 || at > MAX_EMAIL_LOCAL_LENGTH) return null;
  return EMAIL_RE.test(email) ? email : null;
}

/**
 * Returns a list of human-readable problems (empty list means the password is
 * acceptable). Length rules follow NIST SP 800-63B: favour length over
 * composition rules, and block the obvious.
 */
function validatePassword(password, email) {
  if (typeof password !== 'string') return ['Password must be a string.'];

  const problems = [];
  const length = [...password].length; // count characters, not UTF-16 units

  if (length < MIN_PASSWORD_LENGTH) {
    problems.push(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`);
  }
  if (length > MAX_PASSWORD_LENGTH) {
    problems.push(`Password must be at most ${MAX_PASSWORD_LENGTH} characters long.`);
  }

  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) {
    problems.push('Password is too common.');
  }
  if (length > 0 && /^(.)\1*$/su.test(password)) {
    problems.push('Password cannot be one repeated character.');
  }
  if (email) {
    const local = email.split('@')[0];
    if (local.length >= 4 && lower.includes(local)) {
      problems.push('Password must not contain the name part of your email.');
    }
  }
  return problems;
}

module.exports = {
  normalizeEmail,
  validatePassword,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_EMAIL_LENGTH,
};
