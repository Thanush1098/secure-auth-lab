'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { hashPassword, verifyPassword, DEFAULT_PARAMS } = require('./password');
const { normalizeEmail, validatePassword, MAX_EMAIL_LENGTH } = require('./validation');
const { RateLimiter } = require('./rateLimiter');
const { SessionStore } = require('./sessions');

const MAX_BODY_BYTES = 10 * 1024;
const MAX_LOGIN_PASSWORD_UNITS = 1024;
const GENERIC_LOGIN_ERROR = 'Invalid email or password';

class HttpError extends Error {
  constructor(status, publicMessage, extra = {}) {
    super(publicMessage);
    this.status = status;
    this.publicMessage = publicMessage;
    this.extra = extra;
  }
}

const fingerprint = (value) => crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);

function defaultLogger(event, fields) {
  console.log(JSON.stringify({ time: new Date().toISOString(), event, ...fields }));
}

function createApp(options = {}) {
  const config = {
    secureCookies: options.secureCookies !== false,
    idleMs: options.idleMs ?? 15 * 60 * 1000,
    absoluteMs: options.absoluteMs ?? 8 * 60 * 60 * 1000,
    trustProxy: options.trustProxy === true,
    now: options.now ?? Date.now,
    hashParams: options.hashParams ?? DEFAULT_PARAMS,
    logger: options.logger ?? defaultLogger,
    limits: {
      loginFailuresPerAccountAndIp: 5,
      loginFailuresPerIp: 20,
      loginWindowMs: 15 * 60 * 1000,
      signupsPerIpPerHour: 10,
      requestsPerIpPerMinute: 120,
      ...options.limits,
    },
  };

  const log = (event, fields = {}) => config.logger(event, fields);

  // In-memory stores keep the lab self-contained. Swap for a database in real use.
  const users = new Map(); // email -> { email, passwordHash, createdAt }
  const sessions = new SessionStore({
    idleMs: config.idleMs,
    absoluteMs: config.absoluteMs,
    now: config.now,
  });

  const { limits } = config;
  const requestLimiter = new RateLimiter({ limit: limits.requestsPerIpPerMinute, windowMs: 60 * 1000, now: config.now });
  const signupLimiter = new RateLimiter({ limit: limits.signupsPerIpPerHour, windowMs: 60 * 60 * 1000, now: config.now });
  const accountFailureLimiter = new RateLimiter({ limit: limits.loginFailuresPerAccountAndIp, windowMs: limits.loginWindowMs, now: config.now });
  const ipFailureLimiter = new RateLimiter({ limit: limits.loginFailuresPerIp, windowMs: limits.loginWindowMs, now: config.now });

  // Unknown accounts still pay for one password hash, so response time does not
  // reveal whether an email is registered.
  let dummyHash = null;
  const getDummyHash = () => {
    dummyHash ??= hashPassword(crypto.randomBytes(16).toString('hex'), config.hashParams);
    return dummyHash;
  };

  // ---- cookies ------------------------------------------------------------

  // "__Host-" makes browsers require Secure + Path=/ and forbid a Domain attribute.
  const cookieName = config.secureCookies ? '__Host-sid' : 'sid';

  const cookieAttributes = (maxAgeSec) =>
    ['Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`]
      .concat(config.secureCookies ? ['Secure'] : [])
      .join('; ');

  const sessionCookie = (token, maxAgeSec) => `${cookieName}=${token}; ${cookieAttributes(maxAgeSec)}`;
  const clearCookie = () => `${cookieName}=; ${cookieAttributes(0)}`;

  function getCookie(req, name) {
    const header = req.headers.cookie;
    if (typeof header !== 'string') return null;
    for (const part of header.split(';')) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
    }
    return null;
  }

  // ---- request helpers ----------------------------------------------------

  function clientIp(req) {
    if (config.trustProxy) {
      // Only the LAST entry was added by our own proxy; earlier ones are client-supplied.
      const forwarded = req.headers['x-forwarded-for'];
      if (typeof forwarded === 'string') {
        const parts = forwarded.split(',').map((s) => s.trim()).filter(Boolean);
        if (parts.length > 0) return parts[parts.length - 1];
      }
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function setSecurityHeaders(res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (config.secureCookies) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
  }

  function sendJson(res, status, body) {
    res.statusCode = status;
    res.end(JSON.stringify(body));
  }

  // CSRF defence in depth on top of SameSite=Strict: refuse state-changing
  // requests that the browser says come from another site.
  function assertSameOrigin(req) {
    const fetchSite = req.headers['sec-fetch-site'];
    if (fetchSite !== undefined && fetchSite !== 'same-origin' && fetchSite !== 'none') {
      throw new HttpError(403, 'Forbidden');
    }
    const origin = req.headers.origin;
    if (origin === undefined) return;
    let host;
    try {
      host = new URL(origin).host;
    } catch {
      throw new HttpError(403, 'Forbidden');
    }
    if (host !== req.headers.host) throw new HttpError(403, 'Forbidden');
  }

  function readJsonBody(req) {
    return new Promise((resolve, reject) => {
      const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      if (type !== 'application/json') {
        reject(new HttpError(415, 'Content-Type must be application/json'));
        return;
      }
      if (Number(req.headers['content-length']) > MAX_BODY_BYTES) {
        reject(new HttpError(413, 'Request body too large'));
        return;
      }

      const chunks = [];
      let size = 0;
      let tooLarge = false;

      req.on('data', (chunk) => {
        if (tooLarge) return;
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          tooLarge = true;
          chunks.length = 0;
          reject(new HttpError(413, 'Request body too large'));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (tooLarge) return;
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
          resolve(parsed);
        } catch {
          reject(new HttpError(400, 'Invalid JSON body'));
        }
      });
      req.on('error', reject);
    });
  }

  // ---- route handlers -----------------------------------------------------

  async function handleSignup(req, res, { ip }) {
    const limit = signupLimiter.hit(ip);
    if (limit.blocked) {
      log('rate_limited', { scope: 'signup', ip });
      throw new HttpError(429, 'Too many sign-up attempts. Try again later.', { retryAfter: limit.retryAfterSec });
    }

    const body = await readJsonBody(req);
    const email = normalizeEmail(body.email);
    const problems = [];
    if (!email) problems.push('A valid email address is required.');
    problems.push(...validatePassword(body.password, email));
    if (problems.length > 0) {
      throw new HttpError(400, 'Invalid input', { details: problems });
    }

    // Hash before checking for duplicates so both outcomes take the same time.
    const passwordHash = await hashPassword(body.password, config.hashParams);
    if (users.has(email)) {
      log('signup_rejected', { ip, user: fingerprint(email) });
      throw new HttpError(400, 'Unable to create account with those details');
    }
    users.set(email, { email, passwordHash, createdAt: new Date(config.now()).toISOString() });
    log('signup', { ip, user: fingerprint(email) });
    sendJson(res, 201, { message: 'Account created' });
  }

  async function handleLogin(req, res, { ip }) {
    const body = await readJsonBody(req);
    if (typeof body.email !== 'string' || typeof body.password !== 'string') {
      throw new HttpError(400, 'Email and password are required');
    }

    const email = body.email.trim().toLowerCase().slice(0, MAX_EMAIL_LENGTH);
    const accountKey = `${ip}|${email}`;

    // Per (IP + account) stops password guessing against one account without
    // letting a stranger lock the real owner out from a different address.
    // Per IP stops one address from spraying guesses across many accounts.
    const blocked = [accountFailureLimiter.peek(accountKey), ipFailureLimiter.peek(ip)].find((r) => r.blocked);
    if (blocked) {
      log('login_blocked', { ip, user: fingerprint(email) });
      throw new HttpError(429, 'Too many failed attempts. Try again later.', { retryAfter: blocked.retryAfterSec });
    }

    const user = users.get(email);
    const storedHash = user ? user.passwordHash : await getDummyHash();
    const candidate = body.password.length <= MAX_LOGIN_PASSWORD_UNITS ? body.password : '';
    const passwordMatches = await verifyPassword(candidate, storedHash);

    if (!user || !passwordMatches) {
      accountFailureLimiter.hit(accountKey);
      ipFailureLimiter.hit(ip);
      log('login_failure', { ip, user: fingerprint(email) });
      // Same status and message whether the email exists or not.
      throw new HttpError(401, GENERIC_LOGIN_ERROR);
    }

    accountFailureLimiter.reset(accountKey);

    // Always issue a brand-new session id on login (prevents session fixation)
    // and retire any session the browser was already holding.
    const previous = getCookie(req, cookieName);
    if (previous) sessions.destroy(previous);
    const token = sessions.create(email);

    res.setHeader('Set-Cookie', sessionCookie(token, Math.min(config.idleMs, config.absoluteMs) / 1000));
    log('login_success', { ip, user: fingerprint(email) });
    sendJson(res, 200, { message: 'Logged in' });
  }

  async function handleLogout(req, res, { ip }) {
    const token = getCookie(req, cookieName);
    if (token) sessions.destroy(token);
    res.setHeader('Set-Cookie', clearCookie());
    log('logout', { ip });
    sendJson(res, 200, { message: 'Logged out' });
  }

  async function handleMe(req, res) {
    const token = getCookie(req, cookieName);
    const session = sessions.get(token);
    if (!session) {
      if (token) res.setHeader('Set-Cookie', clearCookie());
      throw new HttpError(401, 'Authentication required');
    }
    // Slide the cookie lifetime together with the server-side idle timer.
    res.setHeader('Set-Cookie', sessionCookie(token, session.remainingMs / 1000));
    sendJson(res, 200, { email: session.email });
  }

  const routes = {
    '/signup': { POST: handleSignup },
    '/login': { POST: handleLogin },
    '/logout': { POST: handleLogout },
    '/me': { GET: handleMe },
    '/health': { GET: async (req, res) => sendJson(res, 200, { status: 'ok' }) },
  };

  // ---- dispatcher ---------------------------------------------------------

  async function handleRequest(req, res) {
    setSecurityHeaders(res);
    const ip = clientIp(req);

    const budget = requestLimiter.hit(ip);
    if (budget.blocked) {
      log('rate_limited', { scope: 'requests', ip });
      throw new HttpError(429, 'Too many requests', { retryAfter: budget.retryAfterSec });
    }

    let pathname;
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
      throw new HttpError(400, 'Bad request');
    }

    const route = Object.hasOwn(routes, pathname) ? routes[pathname] : null;
    if (!route) throw new HttpError(404, 'Not found');

    const handler = route[req.method];
    if (!handler) throw new HttpError(405, 'Method not allowed', { allow: Object.keys(route).join(', ') });

    if (req.method === 'POST') assertSameOrigin(req);
    await handler(req, res, { ip });
  }

  function sendError(req, res, err) {
    req.resume(); // discard any unread request body
    if (res.writableEnded) return;

    if (err instanceof HttpError) {
      if (err.extra.retryAfter) res.setHeader('Retry-After', String(err.extra.retryAfter));
      if (err.extra.allow) res.setHeader('Allow', err.extra.allow);
      if (err.status === 413) res.setHeader('Connection', 'close');
      const body = { error: err.publicMessage };
      if (err.extra.details) body.details = err.extra.details;
      sendJson(res, err.status, body);
      return;
    }

    // Details go to the server log only. The client never sees stack traces,
    // library names or file paths.
    log('internal_error', { error: String(err && err.message ? err.message : err) });
    sendJson(res, 500, { error: 'Internal server error' });
  }

  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((err) => sendError(req, res, err));
  });
  // Basic slow-client protection.
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;

  return { server, users, sessions, config };
}

module.exports = { createApp };
