'use strict';

const crypto = require('node:crypto');

// 32 random bytes encoded as base64url is always 43 characters.
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const PRUNE_THRESHOLD = 1_000;

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

/**
 * Server-side sessions.
 *
 *  - The cookie carries a random 256-bit token with no meaning of its own.
 *  - Only the SHA-256 of the token is stored, so a leaked session table cannot
 *    be replayed as cookies.
 *  - Sessions expire after `idleMs` of inactivity AND after `absoluteMs`
 *    no matter how active they are.
 */
class SessionStore {
  constructor({ idleMs, absoluteMs, now = Date.now }) {
    this.idleMs = idleMs;
    this.absoluteMs = absoluteMs;
    this.now = now;
    this.sessions = new Map();
  }

  create(email) {
    this._prune();
    const token = crypto.randomBytes(32).toString('base64url');
    const t = this.now();
    this.sessions.set(hashToken(token), { email, createdAt: t, lastSeen: t });
    return token;
  }

  /** Returns { email, remainingMs } for a live session (and slides the idle timer), else null. */
  get(token) {
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
    const key = hashToken(token);
    const session = this.sessions.get(key);
    if (!session) return null;

    const now = this.now();
    const idleFor = now - session.lastSeen;
    const age = now - session.createdAt;
    if (idleFor > this.idleMs || age > this.absoluteMs) {
      this.sessions.delete(key);
      return null;
    }
    session.lastSeen = now;
    return { email: session.email, remainingMs: Math.min(this.idleMs, this.absoluteMs - age) };
  }

  destroy(token) {
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) return;
    this.sessions.delete(hashToken(token));
  }

  get size() {
    return this.sessions.size;
  }

  /** Stored lookup keys (hashes). Exposed so tests can prove raw tokens are not kept. */
  keys() {
    return [...this.sessions.keys()];
  }

  _prune() {
    if (this.sessions.size < PRUNE_THRESHOLD) return;
    const now = this.now();
    for (const [key, s] of this.sessions) {
      if (now - s.lastSeen > this.idleMs || now - s.createdAt > this.absoluteMs) {
        this.sessions.delete(key);
      }
    }
  }
}

module.exports = { SessionStore };
