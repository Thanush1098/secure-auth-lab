# Secure Authentication Lab

A small local authentication service built to demonstrate safe password storage, input validation, secure sessions, rate limiting and generic errors. It has **zero dependencies**: only Node.js built-in modules, so there is nothing to install.

**Milestone 3 of 5.** Part of a series that started with a threat model of a notes app (Milestone 2). This lab implements the defences for the authentication-related threats from that model.

## Deliverables in this repository

| Deliverable | Files |
|---|---|
| Working service | [`app.js`](app.js), [`password.js`](password.js), [`validation.js`](validation.js), [`sessions.js`](sessions.js), [`rateLimiter.js`](rateLimiter.js), [`server.js`](server.js) |
| Automated tests (36 tests) | [`password.test.js`](password.test.js), [`validation.test.js`](validation.test.js), [`sessions.test.js`](sessions.test.js), [`ratelimit-and-errors.test.js`](ratelimit-and-errors.test.js), helper: [`helpers.js`](helpers.js) |
| Test output | [`test-output.txt`](test-output.txt) |
| Authentication security note | [`SECURITY_NOTE.md`](SECURITY_NOTE.md) |
| Recorded manual run with curl | [`demo-session.txt`](demo-session.txt) |

## Pass checklist

| Requirement | Implemented as | Proven by |
|---|---|---|
| Password hashing and server-side input validation | scrypt with per-password salt; strict validation of email and password; type, size and content-type checks | `password.test.js`, `validation.test.js` |
| Secure cookie settings, logout and session expiry | `__Host-sid` cookie with HttpOnly, Secure, SameSite=Strict; server-side logout; 15 min idle and 8 h absolute timeouts | `sessions.test.js` |
| Rate limits and generic authentication errors | 5 failures per account and address, 20 per address, sign-up and request limits; identical error for wrong password and unknown email | `ratelimit-and-errors.test.js` |

## Run it

Requires Node.js 20 or newer. No `npm install` needed.

```bash
npm test             # run all tests
npm run start:dev    # start the service on http://127.0.0.1:3000
```

`start:dev` turns off the cookie `Secure` flag so `curl` works over plain HTTP. Use `npm start` (Secure cookies on) whenever the service is behind HTTPS.

### Try it with curl

```bash
# sign up
curl -i -X POST http://127.0.0.1:3000/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"correct horse battery staple"}'

# log in and save the session cookie
curl -i -c jar.txt -X POST http://127.0.0.1:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"correct horse battery staple"}'

# protected route
curl -i -b jar.txt http://127.0.0.1:3000/me

# log out
curl -i -b jar.txt -X POST http://127.0.0.1:3000/logout
```

## API

| Method and path | Purpose | Success | Failure |
|---|---|---|---|
| `POST /signup` | Create an account | 201 | 400 invalid input, 429 too many attempts |
| `POST /login` | Start a session | 200 plus cookie | 401 generic error, 429 blocked |
| `POST /logout` | End the session | 200 | n/a |
| `GET /me` | Protected: who am I | 200 | 401 |
| `GET /health` | Liveness check | 200 | n/a |

## What each file does

| File | Purpose |
|---|---|
| `app.js` | HTTP server, routes, cookies, CSRF check, error handling |
| `password.js` | scrypt hashing and constant-time verification |
| `validation.js` | Email and password rules |
| `sessions.js` | Server-side sessions with idle and absolute expiry |
| `rateLimiter.js` | Fixed-window limiter |
| `server.js` | Entry point (binds to 127.0.0.1) |
| `helpers.js` | Shared test helpers (small HTTP client, fake clock) |
| `*.test.js` | Automated tests, run with Node's built-in test runner |

## Configuration

See [`.env.example`](.env.example). The service needs no secrets. `COOKIE_SECURE` and `TRUST_PROXY` are behaviour switches only. `.env` is git-ignored and must never be committed.

## Limits

This is a learning lab, not a production system: data is held in memory, there is no HTTPS in the app itself, and features such as MFA, password reset and email verification are intentionally left out. The full list is in [`SECURITY_NOTE.md`](SECURITY_NOTE.md).
