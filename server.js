const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const PORT = process.env.PORT || 8765;
const HOST = process.env.HOST || '127.0.0.1';
const MAX_BODY = 1024 * 1024;

const GEMINI_SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

function getGeminiOAuthCreds() {
  const { execSync } = require('child_process');
  try {
    const geminiPath = execSync('which gemini', { encoding: 'utf8' }).trim();
    const realPath = fs.realpathSync(geminiPath);
    const pkgRoot = path.resolve(path.dirname(realPath), '..');
    const oauth2Path = path.join(pkgRoot, 'node_modules', '@google', 'gemini-cli-core', 'dist', 'src', 'code_assist', 'oauth2.js');
    const src = fs.readFileSync(oauth2Path, 'utf8');
    const idMatch = src.match(/OAUTH_CLIENT_ID\s*=\s*['"]([^'"]+)['"]/);
    const secretMatch = src.match(/OAUTH_CLIENT_SECRET\s*=\s*['"]([^'"]+)['"]/);
    if (idMatch && secretMatch) return { clientId: idMatch[1], clientSecret: secretMatch[1] };
  } catch {}
  try {
    const { execSync: ex } = require('child_process');
    const npxDirs = fs.readdirSync(path.join(os.homedir(), '.npm', '_npx')).filter(d => !d.startsWith('.'));
    for (const d of npxDirs) {
      const oauth2Path = path.join(os.homedir(), '.npm', '_npx', d, 'node_modules', '@google', 'gemini-cli-core', 'dist', 'src', 'code_assist', 'oauth2.js');
      if (fs.existsSync(oauth2Path)) {
        const src = fs.readFileSync(oauth2Path, 'utf8');
        const idMatch = src.match(/OAUTH_CLIENT_ID\s*=\s*['"]([^'"]+)['"]/);
        const secretMatch = src.match(/OAUTH_CLIENT_SECRET\s*=\s*['"]([^'"]+)['"]/);
        if (idMatch && secretMatch) return { clientId: idMatch[1], clientSecret: secretMatch[1] };
      }
    }
  } catch {}
  return null;
}
const GEMINI_DIR = path.join(os.homedir(), '.gemini');
const GEMINI_OAUTH_FILE = path.join(GEMINI_DIR, 'oauth_creds.json');
const GEMINI_ACCOUNTS_FILE = path.join(GEMINI_DIR, 'google_accounts.json');

let googleOAuthState = { status: 'idle', error: null, email: null };
let googleOAuthPending = null;

const PROVIDER_CONFIGS = {
  'anthropic': {
    configPaths: [
      path.join(os.homedir(), '.claude.json'),
      path.join(os.homedir(), '.config', 'claude', 'settings.json'),
      path.join(os.homedir(), '.anthropic.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      default_model: model
    })
  },
  'openai': {
    configPaths: [
      path.join(os.homedir(), '.openai.json'),
      path.join(os.homedir(), '.config', 'openai', 'api-key')
    ],
    configFormat: (apiKey, model) => ({
      apiKey: apiKey,
      defaultModel: model
    })
  },
  'google': {
    configPaths: [
      path.join(os.homedir(), '.gemini.json'),
      path.join(os.homedir(), '.config', 'gemini', 'credentials.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      default_model: model
    })
  },
  'openrouter': {
    configPaths: [
      path.join(os.homedir(), '.openrouter.json'),
      path.join(os.homedir(), '.config', 'openrouter', 'config.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      default_model: model
    })
  },
  'github': {
    configPaths: [
      path.join(os.homedir(), '.github.json'),
      path.join(os.homedir(), '.config', 'github-copilot.json')
    ],
    configFormat: (apiKey, model) => ({
      github_token: apiKey,
      default_model: model
    })
  },
  'azure': {
    configPaths: [
      path.join(os.homedir(), '.azure.json'),
      path.join(os.homedir(), '.config', 'azure-openai', 'config.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      endpoint: '',
      default_model: model
    })
  },
  'anthropic-claude-code': {
    configPaths: [
      path.join(os.homedir(), '.claude', 'max.json'),
      path.join(os.homedir(), '.config', 'claude-code', 'max.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      plan: 'max',
      default_model: model
    })
  },
  'opencode': {
    configPaths: [
      path.join(os.homedir(), '.opencode', 'config.json'),
      path.join(os.homedir(), '.config', 'opencode', 'config.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      default_model: model,
      providers: ['anthropic', 'openai', 'google']
    })
  },
  'proxypilot': {
    configPaths: [
      path.join(os.homedir(), '.proxypilot', 'config.json'),
      path.join(os.homedir(), '.config', 'proxypilot', 'config.json')
    ],
    configFormat: (apiKey, model) => ({
      api_key: apiKey,
      default_model: model
    })
  }
};

function maskKey(key) {
  if (!key || key.length < 8) return '****';
  return '****' + key.slice(-4);
}

function validateSaveInput(body) {
  if (!body || typeof body !== 'object') return 'Invalid request body';
  const { providerId, apiKey, defaultModel } = body;
  if (typeof providerId !== 'string' || !providerId.length || providerId.length > 100) return 'Invalid providerId';
  if (typeof apiKey !== 'string' || !apiKey.length || apiKey.length > 10000) return 'Invalid apiKey';
  if (defaultModel !== undefined && (typeof defaultModel !== 'string' || defaultModel.length > 200)) return 'Invalid defaultModel';
  return null;
}

function getGeminiOAuthStatus() {
  try {
    if (fs.existsSync(GEMINI_OAUTH_FILE)) {
      const creds = JSON.parse(fs.readFileSync(GEMINI_OAUTH_FILE, 'utf8'));
      if (creds.refresh_token || creds.access_token) {
        let email = '';
        try {
          if (fs.existsSync(GEMINI_ACCOUNTS_FILE)) {
            const accts = JSON.parse(fs.readFileSync(GEMINI_ACCOUNTS_FILE, 'utf8'));
            email = accts.active || '';
          }
        } catch (_) {}
        return { hasKey: true, apiKey: email ? email : '****oauth', defaultModel: '', path: GEMINI_OAUTH_FILE, authMethod: 'oauth' };
      }
    }
  } catch (_) {}
  return null;
}

function getConfigs() {
  const configs = {};

  for (const [providerId, config] of Object.entries(PROVIDER_CONFIGS)) {
    if (providerId === 'google') {
      const oauthStatus = getGeminiOAuthStatus();
      if (oauthStatus) {
        configs[providerId] = oauthStatus;
        continue;
      }
    }
    for (const configPath of config.configPaths) {
      try {
        if (fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf8');
          const parsed = JSON.parse(content);
          const rawKey = parsed.api_key || parsed.apiKey || parsed.github_token || '';
          configs[providerId] = {
            apiKey: maskKey(rawKey),
            hasKey: !!rawKey,
            defaultModel: parsed.default_model || parsed.defaultModel || '',
            path: configPath
          };
          break;
        }
      } catch (e) {
        console.error(`Error reading ${configPath}:`, e.message);
      }
    }
  }

  return configs;
}

function saveConfig(providerId, apiKey, defaultModel) {
  const config = PROVIDER_CONFIGS[providerId];
  if (!config) {
    throw new Error(`Unknown provider: ${providerId}`);
  }

  const configPath = config.configPaths[0];
  const configDir = path.dirname(configPath);

  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }

  let existing = {};
  try {
    if (fs.existsSync(configPath)) {
      existing = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
  } catch (_) {
    // corrupt file, start fresh
  }

  const newData = config.configFormat(apiKey, defaultModel);
  const merged = { ...existing, ...newData };
  fs.writeFileSync(configPath, JSON.stringify(merged, null, 2), { mode: 0o600 });

  return configPath;
}

function getCorsHeaders(req) {
  const origin = req.headers.origin || '';
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

function log(req, status) {
  const ts = new Date().toISOString();
  console.log(`${ts} ${req.method} ${req.url} ${status}`);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      body += chunk;
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

async function saveGeminiCredentials(tokens, email) {
  if (!fs.existsSync(GEMINI_DIR)) fs.mkdirSync(GEMINI_DIR, { recursive: true });
  fs.writeFileSync(GEMINI_OAUTH_FILE, JSON.stringify(tokens, null, 2), { mode: 0o600 });
  try { fs.chmodSync(GEMINI_OAUTH_FILE, 0o600); } catch (_) {}

  let accounts = { active: null, old: [] };
  try {
    if (fs.existsSync(GEMINI_ACCOUNTS_FILE)) {
      accounts = JSON.parse(fs.readFileSync(GEMINI_ACCOUNTS_FILE, 'utf8'));
    }
  } catch (_) {}

  if (email) {
    if (accounts.active && accounts.active !== email && !accounts.old.includes(accounts.active)) {
      accounts.old.push(accounts.active);
    }
    accounts.active = email;
  }
  fs.writeFileSync(GEMINI_ACCOUNTS_FILE, JSON.stringify(accounts, null, 2), { mode: 0o600 });
}

function buildBaseUrl(req) {
  const override = process.env.AGENTAUTH_BASE_URL;
  if (override) return override.replace(/\/+$/, '');

  const fwdProto = req.headers['x-forwarded-proto'];
  const fwdHost = req.headers['x-forwarded-host'] || req.headers['host'];
  if (fwdHost) {
    const proto = fwdProto || (req.socket.encrypted ? 'https' : 'http');
    const cleanHost = fwdHost
      .replace(/:443$/, '')
      .replace(/:80$/, '');
    const base = `${proto}://${cleanHost}`;
    console.log(`buildBaseUrl: proto=${proto} fwdHost=${fwdHost} -> ${base}`);
    return base;
  }
  console.log(`buildBaseUrl: no forwarded headers, falling back to http://127.0.0.1:${PORT}`);
  return `http://127.0.0.1:${PORT}`;
}

async function startGoogleOAuth(baseUrl) {
  const creds = getGeminiOAuthCreds();
  if (!creds) throw new Error('Could not find Gemini CLI OAuth credentials. Install gemini CLI first.');

  const redirectUri = `${baseUrl}/oauth2callback`;
  const state = crypto.randomBytes(32).toString('hex');

  const client = new OAuth2Client({
    clientId: creds.clientId,
    clientSecret: creds.clientSecret,
  });

  const authUrl = client.generateAuthUrl({
    redirect_uri: redirectUri,
    access_type: 'offline',
    scope: GEMINI_SCOPES,
    state,
  });

  googleOAuthPending = { client, redirectUri, state };
  googleOAuthState = { status: 'pending', error: null, email: null };

  setTimeout(() => {
    if (googleOAuthState.status === 'pending') {
      googleOAuthState = { status: 'error', error: 'Authentication timed out', email: null };
      googleOAuthPending = null;
    }
  }, 5 * 60 * 1000);

  return authUrl;
}

async function handleOAuthCallback(req, res) {
  const reqUrl = new URL(req.url, buildBaseUrl(req));

  if (!googleOAuthPending) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthResultPage('Authentication Failed', 'No pending OAuth flow. Please start authentication again.', false));
    return;
  }

  const { client, redirectUri, state: expectedState } = googleOAuthPending;

  try {
    const error = reqUrl.searchParams.get('error');
    if (error) {
      const desc = reqUrl.searchParams.get('error_description') || error;
      googleOAuthState = { status: 'error', error: desc, email: null };
      googleOAuthPending = null;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(oauthResultPage('Authentication Failed', desc, false));
      return;
    }

    const returnedState = reqUrl.searchParams.get('state');
    if (returnedState !== expectedState) {
      googleOAuthState = { status: 'error', error: 'State mismatch', email: null };
      googleOAuthPending = null;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(oauthResultPage('Authentication Failed', 'State mismatch - possible CSRF attack.', false));
      return;
    }

    const code = reqUrl.searchParams.get('code');
    if (!code) {
      googleOAuthState = { status: 'error', error: 'No authorization code received', email: null };
      googleOAuthPending = null;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(oauthResultPage('Authentication Failed', 'No authorization code received.', false));
      return;
    }

    const { tokens } = await client.getToken({ code, redirect_uri: redirectUri });
    client.setCredentials(tokens);

    let email = '';
    try {
      const { token } = await client.getAccessToken();
      if (token) {
        const resp = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (resp.ok) {
          const info = await resp.json();
          email = info.email || '';
        }
      }
    } catch (_) {}

    await saveGeminiCredentials(tokens, email);
    googleOAuthState = { status: 'success', error: null, email };
    googleOAuthPending = null;

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthResultPage('Authentication Successful', email ? `Signed in as ${email}` : 'Gemini CLI credentials saved.', true));
  } catch (e) {
    googleOAuthState = { status: 'error', error: e.message, email: null };
    googleOAuthPending = null;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthResultPage('Authentication Failed', e.message, false));
  }
}

function oauthResultPage(title, message, success) {
  const color = success ? '#10b981' : '#ef4444';
  const icon = success ? '&#10003;' : '&#10007;';
  return `<!DOCTYPE html><html><head><title>${title}</title></head>
<body style="margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#111827;font-family:system-ui,sans-serif;color:white;">
<div style="text-align:center;max-width:400px;padding:2rem;">
<div style="font-size:4rem;color:${color};margin-bottom:1rem;">${icon}</div>
<h1 style="font-size:1.5rem;margin-bottom:0.5rem;">${title}</h1>
<p style="color:#9ca3af;">${message}</p>
<p style="color:#6b7280;margin-top:1rem;font-size:0.875rem;">You can close this tab.</p>
</div></body></html>`;
}

const server = http.createServer(async (req, res) => {
  const corsHeaders = getCorsHeaders(req);
  for (const [k, v] of Object.entries(corsHeaders)) {
    res.setHeader(k, v);
  }

  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      log(req, 204);
      return;
    }

    if (req.url === '/api/configs' && req.method === 'GET') {
      const configs = getConfigs();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(configs));
      log(req, 200);
      return;
    }

    if (req.url === '/api/save-config' && req.method === 'POST') {
      const contentType = req.headers['content-type'] || '';
      if (!contentType.includes('application/json')) {
        res.writeHead(415, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
        log(req, 415);
        return;
      }

      let body;
      try {
        const raw = await readBody(req);
        body = JSON.parse(raw);
      } catch (e) {
        const status = e.message === 'Request body too large' ? 413 : 400;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, status);
        return;
      }

      const validationError = validateSaveInput(body);
      if (validationError) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: validationError }));
        log(req, 400);
        return;
      }

      try {
        const { providerId, apiKey, defaultModel } = body;
        const configPath = saveConfig(providerId, apiKey, defaultModel || '');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, path: configPath }));
        log(req, 200);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, 400);
      }
      return;
    }

    if (req.url === '/api/google-oauth/start' && req.method === 'POST') {
      try {
        const baseUrl = buildBaseUrl(req);
        const authUrl = await startGoogleOAuth(baseUrl);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ authUrl }));
        log(req, 200);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, 500);
      }
      return;
    }

    if (req.url === '/api/google-oauth/status' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(googleOAuthState));
      log(req, 200);
      return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (parsedUrl.pathname === '/oauth2callback' && req.method === 'GET') {
      try {
        await handleOAuthCallback(req, res);
        log(req, 200);
      } catch (e) {
        console.error('OAuth callback error:', e);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(oauthResultPage('Authentication Failed', e.message, false));
        log(req, 500);
      }
      return;
    }

    if (req.url === '/' || req.url === '/index.html') {
      const htmlPath = path.join(__dirname, 'index.html');
      fs.readFile(htmlPath, (err, data) => {
        if (err) {
          res.writeHead(500);
          res.end('Error loading page');
          log(req, 500);
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data);
        log(req, 200);
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
    log(req, 404);
  } catch (e) {
    console.error('Unhandled request error:', e);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    log(req, 500);
  }
});

function shutdown(signal) {
  console.log(`\n${signal} received, shutting down...`);
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('Forced shutdown after timeout.');
    process.exit(1);
  }, 5000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (e) => {
  console.error('Uncaught exception:', e);
});
process.on('unhandledRejection', (e) => {
  console.error('Unhandled rejection:', e);
});

server.listen(PORT, HOST, () => {
  console.log(`Agent Auth server running at http://${HOST}:${PORT}`);
  console.log(`\nSupported providers:`);
  Object.keys(PROVIDER_CONFIGS).forEach(p => console.log(`  - ${p}`));
});
