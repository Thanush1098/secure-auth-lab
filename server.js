'use strict';

const { createApp } = require('./app');

const port = Number(process.env.PORT) || 3000;

const { server } = createApp({
  // Secure cookies need HTTPS. Set COOKIE_SECURE=false only for local curl tests over http.
  secureCookies: process.env.COOKIE_SECURE !== 'false',
  trustProxy: process.env.TRUST_PROXY === 'true',
});

// Bind to localhost only: this is a local lab service.
server.listen(port, '127.0.0.1', () => {
  console.log(`secure-auth-lab listening on http://127.0.0.1:${port}`);
  if (process.env.COOKIE_SECURE === 'false') {
    console.log('WARNING: COOKIE_SECURE=false. Use only for local testing over plain HTTP.');
  }
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
