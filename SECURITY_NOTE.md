# Authentication Security Note

**Project:** Secure Authentication Lab (Milestone 3 of 5)
**Service:** small local authentication service (sign up, log in, log out, one protected route)
**Stack:** Node.js 20+ with only built-in modules (`http`, `crypto`, `node:test`). No runtime dependencies.

This note explains what the service protects against, how each control works, how it was verified, and what it deliberately does **not** cover. It builds on the Milestone 2 threat model: threats T1 (credential stuffing), T3 (verbose errors), T6 (XSS and session theft), T7 (no audit trail) and T8 (unthrottled endpoints) are the ones addressed here. T5 (password reset tokens) is not applicable yet because no reset flow is built (see limitations).

## 1. Controls implemented

### 1.1 Password storage and validation (checklist step 1)

| Control | How it works | Where |
|---|---|---|
| Slow, salted password hashing | scrypt with N=2^15, r=8, p=3 and a random 16-byte salt per password. The cost parameters are stored inside each hash, so they can be raised later without locking anyone out. | `password.js` |
| Constant-time comparison | `crypto.timingSafeEqual` on the derived keys. Malformed or tampered stored hashes count as a failed login, and stored cost parameters are capped so a corrupted record cannot exhaust server memory. | `password.js` |
| Unicode normalization | Passwords are NFKC-normalized before hashing so visually identical passwords match. | `password.js` |
| Server-side validation | Every request is validated on the server (client checks are never trusted): email must be a string in a valid format (max 254 chars), password must be a string of 12 to 128 characters, not a very common password, not one repeated character, and not contain the email name. Wrong data types such as `{"$ne": null}` or arrays are rejected with 400. | `validation.js` |
| Request hygiene | JSON only (415 otherwise), 10 KB body limit (413), body must be a JSON object, emails are trimmed and lower-cased so `Alice@x.com` and `alice@x.com` are one account. | `app.js` |

### 1.2 Cookies, logout and session expiry (checklist step 2)

| Control | How it works | Where |
|---|---|---|
| Random server-side sessions | The cookie holds a random 256-bit token with no meaning of its own. There is no signing key or JWT secret that could leak. | `sessions.js` |
| Token hashed at rest | The server stores only the SHA-256 of each token, so a leaked session table cannot be replayed as cookies. | `sessions.js` |
| Hardened cookie | `__Host-sid` with `HttpOnly` (JavaScript cannot read it, limiting XSS damage), `Secure` (HTTPS only), `SameSite=Strict` (not sent on cross-site requests), `Path=/`, no `Domain` (host-only), and a `Max-Age`. | `app.js` |
| New session id on login | Every login creates a new token and retires any session the browser already held, which prevents session fixation. | `app.js` |
| Real logout | `POST /logout` deletes the session on the server and tells the browser to delete the cookie. A copied cookie stops working immediately. | `app.js` |
| Idle timeout | 15 minutes without activity ends the session. Activity slides the timer. | `sessions.js` |
| Absolute timeout | 8 hours after login the session ends no matter how active it is. | `sessions.js` |
| CSRF defence in depth | On top of `SameSite=Strict`, state-changing requests are refused with 403 if the browser reports a cross-site `Sec-Fetch-Site` or an `Origin` that does not match the host. | `app.js` |
| Response headers | `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy`, `Referrer-Policy: no-referrer`, and HSTS when secure cookies are on. | `app.js` |

### 1.3 Rate limits and generic errors (checklist step 3)

| Control | How it works | Where |
|---|---|---|
| Failed-login limit per account and address | 5 failures in 15 minutes for the same account from the same address, then 429 with `Retry-After`, even if the next password is correct. A success resets the counter. | `app.js`, `rateLimiter.js` |
| Failed-login limit per address | 20 failures in 15 minutes from one address across all accounts, which stops password spraying. | same |
| Sign-up limit | 10 sign-ups per address per hour. | same |
| Overall request budget | 120 requests per address per minute. | same |
| Generic login errors | Wrong password and unknown email return the identical status and body: `401 {"error":"Invalid email or password"}`. | `app.js` |
| No timing leak for unknown emails | Unknown accounts still run one full password hash, so response time does not reveal whether an email exists. | `app.js` |
| No internals in errors | Unexpected failures return `500 {"error":"Internal server error"}`. Details go only to the server log. Unknown routes return a plain 404 and wrong methods a 405. | `app.js` |
| Safe audit log | Signup, login success and failure, blocks, logouts and internal errors are logged as JSON lines. Passwords, session tokens and raw email addresses are never logged (emails appear only as a short hash). | `app.js` |

## 2. Design decisions worth explaining

- **Why not lock accounts outright?** A plain "lock after 5 failures" lets anyone lock a victim out by guessing wrong on purpose. The limit is keyed by address plus account, with a separate per-address ceiling, so an attacker is throttled while the real owner on another address can still log in. This is tested.
- **Why server-side sessions instead of JWTs?** They can be revoked instantly (logout works for real), nothing in the cookie can be forged or decoded, and there is no signing secret to protect.
- **Why scrypt and no bcrypt package?** scrypt is built into Node and is an accepted OWASP option, so the project has zero dependencies, nothing to install, and nothing for `npm audit` to flag.
- **Why a 12 character minimum with no composition rules?** Following NIST SP 800-63B, length and a block on obvious passwords help more than forced symbols.

## 3. How it was verified

Automated tests (`npm test`, 36 tests in 4 files, all passing, output saved in `test-output.txt`):

| Area | What the tests prove |
|---|---|
| Hashing | Salted scrypt format with the production cost; same password hashes differently; malformed hashes fail closed; stored record never contains the plaintext. |
| Validation | Weak or too-long passwords, bad emails, wrong types, bad JSON, wrong content type and oversized bodies are all rejected; email case variants cannot create duplicates. |
| Cookies and sessions | Cookie flags, 256-bit token, only a hash stored server-side, logout kills the session, idle and absolute timeouts, new id per login, CSRF refusals. |
| Rate limits and errors | 6th attempt blocked then recovers, reset on success, no cross-address lockout, spraying blocked, sign-up and request limits, identical errors for unknown email and wrong password, no internals in 500 errors, secrets absent from logs. |

**Mutation check.** To confirm the tests would catch real mistakes, 11 deliberate bugs were introduced into a scratch copy (for example removing `HttpOnly`, skipping the logout, storing the plaintext password, leaking a stack trace, reusing the session id). Every one made at least one test fail. The suite was also run 5 times in a row with no flaky results.

A live run with `curl` against the real server is recorded in `demo-session.txt`.

## 4. Known limitations (not covered)

Being clear about these matters more than pretending the lab is production ready.

1. **In-memory storage.** Accounts, sessions and rate-limit counters disappear on restart and are not shared between processes. A real deployment needs a database and a shared store such as Redis.
2. **No HTTPS in the app.** Secure cookies and HSTS assume TLS terminated by a reverse proxy. `TRUST_PROXY=true` must be set only behind a proxy you control, or `X-Forwarded-For` could be spoofed to dodge rate limits.
3. **Account enumeration at sign-up.** A duplicate email returns a generic message, but a valid-looking sign-up that succeeds versus fails still reveals whether an address is registered. Fixing this properly needs email verification, which is out of scope. The sign-up limit reduces the abuse.
4. **No breached-password check.** The deny-list is tiny. Production should check candidates against a breached-password service.
5. **Not included:** multi-factor authentication, password reset, email verification, account recovery and password change. These are separate, higher-risk features. A password reset flow in particular must be threat-modelled before it is built (see T5).
6. **Fixed-window rate limiting** allows a short burst around a window boundary. A sliding window or token bucket would be smoother.
7. **No penetration test.** Verification here is by unit and integration tests and one manual run, not an independent assessment.

## 5. Running it

```bash
npm test                 # run the automated tests (no install needed)
npm run start:dev        # start on http://127.0.0.1:3000 with cookies usable over plain HTTP
```

All passwords in tests and demos are fake. The repository contains no real secrets, and `.env` is git-ignored.
