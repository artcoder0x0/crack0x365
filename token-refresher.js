#!/usr/bin/env node
// ╔══════════════════════════════════════════════════════════════╗
// ║  M365 Token Refresher Server                                 ║
// ║  POST /refresh  →  refresh token, return new token data      ║
// ║  Runs on http://localhost:3737                               ║
// ╚══════════════════════════════════════════════════════════════╝
//
// Usage:
//   node token-refresher.js
//   node token-refresher.js --port 3737
//
// The mail client POSTs to http://localhost:3737/refresh with:
//   { "tokenFilePath": "/absolute/path/to/tokens_XXXX.json" }
//     OR
//   { "tokenData": { ...full tokens JSON object... } }
//
// The server:
//   1. Reads the file (or uses tokenData)
//   2. Calls AAD v1 /oauth2/token with the refresh_token
//   3. Overwrites the file in-place (same path, same name)
//   4. Returns the fresh token JSON so the client can use it immediately
//
// CORS: allows localhost origins so the HTML mail client can call it directly.

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT      = process.argv.includes('--port')
  ? parseInt(process.argv[process.argv.indexOf('--port') + 1], 10)
  : 3737;

const CLIENT_ID  = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
const RESOURCE   = 'https://graph.microsoft.com';
const SCOPE      = 'offline_access';
const TOKEN_URL  = 'https://login.microsoftonline.com/common/oauth2/token';

// Track in-flight refresh requests to avoid duplicate concurrent refreshes
// for the same refresh token (key = first 16 chars of refresh_token)
const inflight = new Map();

// ── HTTPS helper ──────────────────────────────────────────────────────────────
function post(url, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const u    = new URL(url);
    const req  = https.request({
      hostname: u.hostname,
      path:     u.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent':     'M365TokenRefresher/1.0',
      },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { reject(new Error('Bad JSON from AAD: ' + raw.slice(0, 300))); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── JWT decoder ───────────────────────────────────────────────────────────────
function decodeJwt(t) {
  try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); }
  catch { return null; }
}

// ── CORS headers ──────────────────────────────────────────────────────────────
const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type':                 'application/json',
};

function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(statusCode, { ...CORS_HEADERS, 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

// ── Core refresh logic ────────────────────────────────────────────────────────
async function refreshToken(refreshToken) {
  const key = refreshToken.slice(0, 16);

  // Deduplicate concurrent refresh calls for the same token
  if (inflight.has(key)) {
    console.log(`  [dedup] waiting on existing refresh for ...${key}`);
    return inflight.get(key);
  }

  const promise = post(TOKEN_URL, {
    grant_type:    'refresh_token',
    client_id:     CLIENT_ID,
    refresh_token: refreshToken,
    resource:      RESOURCE,
    scope:         SCOPE,
  }).then(res => {
    inflight.delete(key);
    if (res.error) throw new Error(`AAD error: ${res.error} — ${res.error_description || ''}`);
    return res;
  }).catch(e => {
    inflight.delete(key);
    throw e;
  });

  inflight.set(key, promise);
  return promise;
}

// Build enriched token file payload (same structure as devicelogin.js)
function buildTokenPayload(tokens, existingFilePath) {
  const decoded   = decodeJwt(tokens.access_token);
  const expiresAt = Date.now() + (parseInt(tokens.expires_in, 10) || 3600) * 1000;
  return {
    saved_at:        new Date().toISOString(),
    expires_at:      new Date(expiresAt).toISOString(),
    token_file:      existingFilePath ? path.basename(existingFilePath) : 'tokens_refreshed.json',
    access_token:    tokens.access_token,
    refresh_token:   tokens.refresh_token || null,
    expires_in:      tokens.expires_in,
    resource:        tokens.resource || RESOURCE,
    decoded_claims:  decoded,
    email:           decoded?.upn || decoded?.unique_name || '',
    name:            decoded?.name || '',
  };
}

// ── Request handler ───────────────────────────────────────────────────────────
async function handleRefresh(req, res) {
  // Read body
  let body = '';
  for await (const chunk of req) body += chunk;

  let payload;
  try { payload = JSON.parse(body); }
  catch { return sendJson(res, 400, { error: 'Invalid JSON body' }); }

  const { tokenFilePath, tokenData } = payload;

  // Resolve source of refresh token
  let storedData = tokenData || null;
  let filePath   = tokenFilePath || null;

  if (!storedData && filePath) {
    // Normalize path (support relative paths relative to server cwd)
    const resolved = path.isAbsolute(filePath) ? filePath : path.resolve(process.cwd(), filePath);
    filePath = resolved;

    if (!fs.existsSync(filePath)) {
      return sendJson(res, 404, { error: `Token file not found: ${filePath}` });
    }
    try {
      storedData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (e) {
      return sendJson(res, 400, { error: `Cannot parse token file: ${e.message}` });
    }
  }

  if (!storedData) {
    return sendJson(res, 400, { error: 'Provide tokenFilePath or tokenData in request body' });
  }

  const rt = storedData.refresh_token;
  if (!rt) {
    return sendJson(res, 400, {
      error:   'No refresh_token in stored data',
      hint:    'This token was generated without offline_access scope. Re-run devicelogin.js.',
    });
  }

  // Check if token is still valid (don't refresh if > 5 min remaining)
  const expiresAt = storedData.expires_at ? new Date(storedData.expires_at).getTime() : 0;
  if (expiresAt > Date.now() + 300_000) {
    console.log(`  [skip] Token still valid until ${new Date(expiresAt).toISOString()} — returning as-is`);
    // Still return success but no refresh needed
    const result = buildTokenPayload({
      access_token:  storedData.access_token,
      refresh_token: storedData.refresh_token,
      expires_in:    Math.round((expiresAt - Date.now()) / 1000),
      resource:      storedData.resource,
    }, filePath);
    return sendJson(res, 200, { refreshed: false, skipped: true, ...result });
  }

  // Do the refresh
  console.log(`  [refresh] Refreshing token for ${storedData.email || 'unknown'}...`);
  let fresh;
  try {
    fresh = await refreshToken(rt);
  } catch (e) {
    console.error(`  [error] Refresh failed: ${e.message}`);
    return sendJson(res, 502, { error: e.message, hint: 'Refresh token may be expired (>90 days unused). Re-run devicelogin.js.' });
  }

  // Build enriched payload
  const enriched = buildTokenPayload(fresh, filePath);

  // Overwrite file in-place if we have a path
  if (filePath) {
    try {
      fs.writeFileSync(filePath, JSON.stringify(enriched, null, 2), 'utf8');
      console.log(`  [saved] → ${filePath}`);
    } catch (e) {
      console.warn(`  [warn] Could not write file: ${e.message}`);
      // Don't fail the request — still return the fresh token
    }
  }

  console.log(`  [ok] Refreshed for ${enriched.email || 'unknown'} → expires ${enriched.expires_at}`);
  return sendJson(res, 200, { refreshed: true, ...enriched });
}

// ── Health check ──────────────────────────────────────────────────────────────
function handleHealth(res) {
  sendJson(res, 200, {
    status:  'ok',
    server:  'M365 Token Refresher',
    version: '1.0.0',
    port:    PORT,
    time:    new Date().toISOString(),
  });
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const method = req.method.toUpperCase();
  const url    = req.url.split('?')[0];

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }

  console.log(`[${new Date().toISOString()}] ${method} ${url}`);

  if (method === 'GET' && (url === '/' || url === '/health')) {
    return handleHealth(res);
  }

  if (method === 'POST' && url === '/refresh') {
    return handleRefresh(req, res).catch(e => {
      console.error('  [uncaught]', e.message);
      sendJson(res, 500, { error: 'Internal server error', detail: e.message });
    });
  }

  sendJson(res, 404, { error: `Unknown route: ${method} ${url}` });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  M365 Token Refresher Server  ✓ Running                     ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  http://127.0.0.1:${String(PORT).padEnd(42)}║`);
  console.log('║                                                              ║');
  console.log('║  Routes:                                                     ║');
  console.log('║    GET  /health     → server status                         ║');
  console.log('║    POST /refresh    → refresh a token                       ║');
  console.log('║                                                              ║');
  console.log('║  Body (POST /refresh):                                       ║');
  console.log('║    { "tokenFilePath": "/path/to/tokens_XXXX.json" }         ║');
  console.log('║      OR                                                      ║');
  console.log('║    { "tokenData": { ...tokens object... } }                 ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('  Waiting for refresh requests...\n');
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\n❌  Port ${PORT} is already in use.`);
    console.error(`   Is another instance running? Try: node token-refresher.js --port 3738\n`);
  } else {
    console.error('\n❌  Server error:', e.message);
  }
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT',  () => { console.log('\n\n  Shutting down…'); server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { server.close(() => process.exit(0)); });