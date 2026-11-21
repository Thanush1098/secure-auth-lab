'use strict';

const PRUNE_THRESHOLD = 10_000;

/**
 * Fixed-window counter keyed by an arbitrary string (IP, IP+account, ...).
 *
 *  - hit(key)  records one event and reports whether that event went over the limit.
 *  - peek(key) reports whether the NEXT event would be blocked, without counting.
 *  - reset(key) forgets a key (used after a successful login).
 *
 * State lives in memory, so it is per process. See SECURITY_NOTE.md.
 */
class RateLimiter {
  constructor({ limit, windowMs, now = Date.now }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
    this.entries = new Map();
  }

  _live(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.resetAt <= this.now()) {
      this.entries.delete(key);
      return null;
    }
    return entry;
  }

  _prune() {
    if (this.entries.size < PRUNE_THRESHOLD) return;
    const now = this.now();
    for (const [key, entry] of this.entries) {
      if (entry.resetAt <= now) this.entries.delete(key);
    }
  }

  _retryAfterSec(entry) {
    return Math.max(1, Math.ceil((entry.resetAt - this.now()) / 1000));
  }

  peek(key) {
    const entry = this._live(key);
    const blocked = entry !== null && entry.count >= this.limit;
    return { blocked, retryAfterSec: blocked ? this._retryAfterSec(entry) : 0 };
  }

  hit(key) {
    this._prune();
    let entry = this._live(key);
    if (entry === null) {
      entry = { count: 0, resetAt: this.now() + this.windowMs };
      this.entries.set(key, entry);
    }
    entry.count += 1;
    const blocked = entry.count > this.limit;
    return { blocked, retryAfterSec: blocked ? this._retryAfterSec(entry) : 0 };
  }

  reset(key) {
    this.entries.delete(key);
  }
}

module.exports = { RateLimiter };
