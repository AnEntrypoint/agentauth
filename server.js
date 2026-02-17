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
  if (process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET) {
    return { clientId: process.env.GOOGLE_OAUTH_CLIENT_ID, clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET, custom: true };
  }
  const { execSync } = require('child_process');
  const oauthRelPath = path.join('node_modules', '@google', 'gemini-cli-core', 'dist', 'src', 'code_assist', 'oauth2.js');
  try {
    const geminiPath = execSync('which gemini', { encoding: 'utf8' }).trim();
    const realPath = fs.realpathSync(geminiPath);
    const pkgRoot = path.resolve(path.dirname(realPath), '..');
    const result = extractOAuthFromFile(path.join(pkgRoot, oauthRelPath));
    if (result) return result;
  } catch {}
  try {
    const npmCacheDirs = new Set();
    const addDir = (d) => { if (d) npmCacheDirs.add(path.join(d, '_npx')); };
    addDir(path.join(os.homedir(), '.npm'));
    addDir(path.join(os.homedir(), '.cache', '.npm'));
    if (process.env.NPM_CACHE) addDir(process.env.NPM_CACHE);
    if (process.env.npm_config_cache) addDir(process.env.npm_config_cache);
    try { addDir(execSync('npm config get cache', { encoding: 'utf8', timeout: 5000 }).trim()); } catch {}
    for (const cacheDir of npmCacheDirs) {
      if (!fs.existsSync(cacheDir)) continue;
      for (const d of fs.readdirSync(cacheDir).filter(d => !d.startsWith('.'))) {
        const result = extractOAuthFromFile(path.join(cacheDir, d, oauthRelPath));
        if (result) return result;
      }
    }
  } catch {}
  return null;
}

function extractOAuthFromFile(oauth2Path) {
  try {
    const src = fs.readFileSync(oauth2Path, 'utf8');
    const idMatch = src.match(/OAUTH_CLIENT_ID\s*=\s*['"]([^'"]+)['"]/);
    const secretMatch = src.match(/OAUTH_CLIENT_SECRET\s*=\s*['"]([^'"]+)['"]/);
    if (idMatch && secretMatch) return { clientId: idMatch[1], clientSecret: secretMatch[1] };
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
    configPaths: [path.join(os.homedir(), '.claude.json'), path.join(os.homedir(), '.config', 'claude', 'settings.json'), path.join(os.homedir(), '.anthropic.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, default_model: model })
  },
  'openai': {
    configPaths: [path.join(os.homedir(), '.openai.json'), path.join(os.homedir(), '.config', 'openai', 'api-key')],
    configFormat: (apiKey, model) => ({ apiKey, defaultModel: model })
  },
  'google': {
    configPaths: [path.join(os.homedir(), '.gemini.json'), path.join(os.homedir(), '.config', 'gemini', 'credentials.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, default_model: model })
  },
  'openrouter': {
    configPaths: [path.join(os.homedir(), '.openrouter.json'), path.join(os.homedir(), '.config', 'openrouter', 'config.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, default_model: model })
  },
  'github': {
    configPaths: [path.join(os.homedir(), '.github.json'), path.join(os.homedir(), '.config', 'github-copilot.json')],
    configFormat: (apiKey, model) => ({ github_token: apiKey, default_model: model })
  },
  'azure': {
    configPaths: [path.join(os.homedir(), '.azure.json'), path.join(os.homedir(), '.config', 'azure-openai', 'config.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, endpoint: '', default_model: model })
  },
  'anthropic-claude-code': {
    configPaths: [path.join(os.homedir(), '.claude', 'max.json'), path.join(os.homedir(), '.config', 'claude-code', 'max.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, plan: 'max', default_model: model })
  },
  'opencode': {
    configPaths: [path.join(os.homedir(), '.opencode', 'config.json'), path.join(os.homedir(), '.config', 'opencode', 'config.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, default_model: model, providers: ['anthropic', 'openai', 'google'] })
  },
  'proxypilot': {
    configPaths: [path.join(os.homedir(), '.proxypilot', 'config.json'), path.join(os.homedir(), '.config', 'proxypilot', 'config.json')],
    configFormat: (apiKey, model) => ({ api_key: apiKey, default_model: model })
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

async function fetchClaudeUsage(apiKey) {
  try {
    const response = await fetch('https://api.anthropic.com/v1/usage', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Anthropic-Version': '2023-06-01'
      }
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    return null;
  }
}

function getConfigs() {
  const configs = {};
  for (const [providerId, config] of Object.entries(PROVIDER_CONFIGS)) {
    if (providerId === 'google') {
      const oauthStatus = getGeminiOAuthStatus();
      if (oauthStatus) { configs[providerId] = oauthStatus; continue; }
    }
    for (const configPath of config.configPaths) {
      try {
        if (fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf8');
          const parsed = JSON.parse(content);
          const rawKey = parsed.api_key || parsed.apiKey || parsed.github_token || '';
          configs[providerId] = { apiKey: maskKey(rawKey), hasKey: !!rawKey, defaultModel: parsed.default_model || parsed.defaultModel || '', path: configPath };
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
  if (!config) throw new Error(`Unknown provider: ${providerId}`);
  const configPath = config.configPaths[0];
  const configDir = path.dirname(configPath);
  if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
  let existing = {};
  try { if (fs.existsSync(configPath)) existing = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (_) {}
  const merged = { ...existing, ...config.configFormat(apiKey, defaultModel) };
  fs.writeFileSync(configPath, JSON.stringify(merged, null, 2), { mode: 0o600 });
  return configPath;
}

function getCorsHeaders(req) {
  const origin = req.headers.origin || '';
  const headers = { 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
  if (origin) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function log(req, status) {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url} ${status}`);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) { req.destroy(); reject(new Error('Request body too large')); return; }
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
  try { if (fs.existsSync(GEMINI_ACCOUNTS_FILE)) accounts = JSON.parse(fs.readFileSync(GEMINI_ACCOUNTS_FILE, 'utf8')); } catch (_) {}
  if (email) {
    if (accounts.active && accounts.active !== email && !accounts.old.includes(accounts.active)) accounts.old.push(accounts.active);
    accounts.active = email;
  }
  fs.writeFileSync(GEMINI_ACCOUNTS_FILE, JSON.stringify(accounts, null, 2), { mode: 0o600 });
}

function buildBaseUrl(req, customPort) {
  const override = process.env.AGENTGUI_BASE_URL;
  if (override) return override.replace(/\/+$/, '');
  const fwdHost = req.headers['x-forwarded-host'] || req.headers['host'];
  if (fwdHost) {
    const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
    const cleanHost = fwdHost.replace(/:443$/, '').replace(/:80$/, '');
    return `${proto}://${cleanHost}`;
  }
  const port = customPort || PORT;
  return `http://127.0.0.1:${port}`;
}

function encodeOAuthState(csrfToken, relayUrl) {
  const payload = JSON.stringify({ t: csrfToken, r: relayUrl });
  return Buffer.from(payload).toString('base64url');
}

function decodeOAuthState(stateStr) {
  try {
    const payload = JSON.parse(Buffer.from(stateStr, 'base64url').toString());
    return { csrfToken: payload.t, relayUrl: payload.r };
  } catch (_) {
    return { csrfToken: stateStr, relayUrl: null };
  }
}

async function startGoogleOAuth(req, customPort) {
  const creds = getGeminiOAuthCreds();
  if (!creds) throw new Error('Could not find Gemini CLI OAuth credentials. Install gemini CLI first.');

  const useCustomClient = !!creds.custom;
  let redirectUri;
  if (useCustomClient && req) {
    redirectUri = `${buildBaseUrl(req, customPort)}/oauth2callback`;
  } else {
    redirectUri = `http://localhost:${customPort || PORT}/oauth2callback`;
  }

  const csrfToken = crypto.randomBytes(32).toString('hex');
  const relayUrl = req ? `${buildBaseUrl(req, customPort)}/api/google-oauth/relay` : null;
  const state = encodeOAuthState(csrfToken, relayUrl);

  const client = new OAuth2Client({ clientId: creds.clientId, clientSecret: creds.clientSecret });
  const authUrl = client.generateAuthUrl({ redirect_uri: redirectUri, access_type: 'offline', scope: GEMINI_SCOPES, state });

  googleOAuthPending = { client, redirectUri, state: csrfToken };
  googleOAuthState = { status: 'pending', error: null, email: null };

  setTimeout(() => {
    if (googleOAuthState.status === 'pending') {
      googleOAuthState = { status: 'error', error: 'Authentication timed out', email: null };
      googleOAuthPending = null;
    }
  }, 5 * 60 * 1000);

  return authUrl;
}

async function exchangeOAuthCode(code, stateParam) {
  if (!googleOAuthPending) throw new Error('No pending OAuth flow. Please start authentication again.');

  const { client, redirectUri, state: expectedCsrf } = googleOAuthPending;
  const { csrfToken } = decodeOAuthState(stateParam);

  if (csrfToken !== expectedCsrf) {
    googleOAuthState = { status: 'error', error: 'State mismatch', email: null };
    googleOAuthPending = null;
    throw new Error('State mismatch - possible CSRF attack.');
  }

  if (!code) {
    googleOAuthState = { status: 'error', error: 'No authorization code received', email: null };
    googleOAuthPending = null;
    throw new Error('No authorization code received.');
  }

  const { tokens } = await client.getToken({ code, redirect_uri: redirectUri });
  client.setCredentials(tokens);

  let email = '';
  try {
    const { token } = await client.getAccessToken();
    if (token) {
      const resp = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${token}` } });
      if (resp.ok) { const info = await resp.json(); email = info.email || ''; }
    }
  } catch (_) {}

  await saveGeminiCredentials(tokens, email);
  googleOAuthState = { status: 'success', error: null, email };
  googleOAuthPending = null;
  return email;
}

function oauthRelayPage(code, state, error) {
  const stateData = decodeOAuthState(state || '');
  const relayUrl = stateData.relayUrl || '';
  const escapedCode = (code || '').replace(/['"\\]/g, '');
  const escapedState = (state || '').replace(/['"\\]/g, '');
  const escapedError = (error || '').replace(/['"\\]/g, '');
  const escapedRelay = relayUrl.replace(/['"\\]/g, '');

  return `<!DOCTYPE html><html><head><title>Completing sign-in...</title></head>
<body style="margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#111827;font-family:system-ui,sans-serif;color:white;">
<div id="status" style="text-align:center;max-width:400px;padding:2rem;">
<div id="spinner" style="font-size:2rem;margin-bottom:1rem;">&#8987;</div>
<h1 id="title" style="font-size:1.5rem;margin-bottom:0.5rem;">Completing sign-in...</h1>
<p id="msg" style="color:#9ca3af;">Relaying authentication to server...</p>
</div>
<script>
(function() {
  var code = '${escapedCode}';
  var state = '${escapedState}';
  var error = '${escapedError}';
  var relayUrl = '${escapedRelay}';

  function show(icon, title, msg, color) {
    document.getElementById('spinner').textContent = icon;
    document.getElementById('spinner').style.color = color;
    document.getElementById('title').textContent = title;
    document.getElementById('msg').textContent = msg;
  }

  if (error) {
    show('\\u2717', 'Authentication Failed', error, '#ef4444');
    return;
  }

  if (!code) {
    show('\\u2717', 'Authentication Failed', 'No authorization code received.', '#ef4444');
    return;
  }

  if (!relayUrl) {
    show('\\u2713', 'Authentication Successful', 'Credentials saved. You can close this tab.', '#10b981');
    return;
  }

  fetch(relayUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: code, state: state })
  }).then(function(r) { return r.json(); }).then(function(data) {
    if (data.success) {
      show('\\u2713', 'Authentication Successful', data.email ? 'Signed in as ' + data.email + '. You can close this tab.' : 'Credentials saved. You can close this tab.', '#10b981');
    } else {
      show('\\u2717', 'Authentication Failed', data.error || 'Unknown error', '#ef4444');
    }
  }).catch(function(e) {
    show('\\u2717', 'Relay Failed', 'Could not reach server: ' + e.message + '. You may need to paste the URL manually.', '#ef4444');
  });
})();
</script>
</body></html>`;
}

function oauthResultPage(title, message, success) {
  var color = success ? '#10b981' : '#ef4444';
  var icon = success ? '&#10003;' : '&#10007;';
  return `<!DOCTYPE html><html><head><title>${title}</title></head>
<body style="margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#111827;font-family:system-ui,sans-serif;color:white;">
<div style="text-align:center;max-width:400px;padding:2rem;">
<div style="font-size:4rem;color:${color};margin-bottom:1rem;">${icon}</div>
<h1 style="font-size:1.5rem;margin-bottom:0.5rem;">${title}</h1>
<p style="color:#9ca3af;">${message}</p>
<p style="color:#6b7280;margin-top:1rem;font-size:0.875rem;">You can close this tab.</p>
</div></body></html>`;
}

async function handleOAuthCallback(req, res) {
  const reqUrl = new URL(req.url, `http://localhost:${PORT}`);
  const code = reqUrl.searchParams.get('code');
  const state = reqUrl.searchParams.get('state');
  const error = reqUrl.searchParams.get('error');
  const errorDesc = reqUrl.searchParams.get('error_description');

  if (error) {
    const desc = errorDesc || error;
    googleOAuthState = { status: 'error', error: desc, email: null };
    googleOAuthPending = null;
  }

  const stateData = decodeOAuthState(state || '');
  if (stateData.relayUrl) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthRelayPage(code, state, errorDesc || error));
    return;
  }

  if (!googleOAuthPending) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthResultPage('Authentication Failed', 'No pending OAuth flow.', false));
    return;
  }

  try {
    if (error) throw new Error(errorDesc || error);
    const email = await exchangeOAuthCode(code, state);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthResultPage('Authentication Successful', email ? `Signed in as ${email}` : 'Gemini CLI credentials saved.', true));
  } catch (e) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(oauthResultPage('Authentication Failed', e.message, false));
  }
}

function createAuthRoutes(baseUrl = '') {
  return {
    async handleConfig(req, res) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getConfigs()));
    },
    
    async handleClaudeUsage(req, res) {
      try {
        const configs = getConfigs();
        const anthropicConfig = configs['anthropic'];
        const claudeCodeMaxConfig = configs['anthropic-claude-code'];
        
        let apiKey = null;
        let configPath = null;
        
        if (claudeCodeMaxConfig && claudeCodeMaxConfig.hasKey) {
          configPath = claudeCodeMaxConfig.path;
        } else if (anthropicConfig && anthropicConfig.hasKey) {
          configPath = anthropicConfig.path;
        }
        
        if (configPath && fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf8');
          const parsed = JSON.parse(content);
          apiKey = parsed.api_key || parsed.apiKey || '';
        }
        
        if (!apiKey) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No API key configured' }));
          return;
        }
        
        const planType = parsed.plan || 'max';
        const isMax20x = planType === 'max-20x' || planType === 'max_20x';
        
        const now = new Date();
        const next5HourReset = new Date(now.getTime() + 5 * 60 * 60 * 1000);
        const nextWeeklyReset = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        
        const limits = {
          fiveHour: isMax20x ? 900 : 225,
          weekly: isMax20x ? 20000 : 5000
        };
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          plan: isMax20x ? 'Max 20x' : 'Max 5x',
          limits,
          windows: {
            fiveHour: {
              limit: limits.fiveHour,
              resetAt: next5HourReset.toISOString(),
              description: 'Messages per 5-hour window'
            },
            weekly: {
              limit: limits.weekly,
              resetAt: nextWeeklyReset.toISOString(),
              description: 'Messages per week'
            }
          },
          note: 'Usage tracking is based on plan limits. Actual usage may vary.'
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    },
    
    async handleSaveConfig(req, res) {
      if (!(req.headers['content-type'] || '').includes('application/json')) {
        res.writeHead(415, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
        return;
      }
      let body;
      try { body = JSON.parse(await readBody(req)); } catch (e) {
        const status = e.message === 'Request body too large' ? 413 : 400;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        return;
      }
      const err = validateSaveInput(body);
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err }));
        return;
      }
      try {
        const configPath = saveConfig(body.providerId, body.apiKey, body.defaultModel || '');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, path: configPath }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    },
    
    async handleGoogleOAuthStart(req, res) {
      try {
        const authUrl = await startGoogleOAuth(req);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ authUrl }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    },
    
    async handleGoogleOAuthStatus(req, res) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(googleOAuthState));
    },
    
    async handleGoogleOAuthRelay(req, res) {
      try {
        const body = JSON.parse(await readBody(req));
        const { code, state: stateParam } = body;
        if (!code || !stateParam) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing code or state' }));
          return;
        }
        const email = await exchangeOAuthCode(code, stateParam);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, email }));
      } catch (e) {
        googleOAuthState = { status: 'error', error: e.message, email: null };
        googleOAuthPending = null;
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    },
    
    async handleGoogleOAuthComplete(req, res) {
      try {
        const body = JSON.parse(await readBody(req));
        const pastedUrl = (body.url || '').trim();
        if (!pastedUrl) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No URL provided' }));
          return;
        }
        let parsed;
        try { parsed = new URL(pastedUrl); } catch (_) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid URL. Paste the full URL from the browser address bar.' }));
          return;
        }
        const error = parsed.searchParams.get('error');
        if (error) {
          const desc = parsed.searchParams.get('error_description') || error;
          googleOAuthState = { status: 'error', error: desc, email: null };
          googleOAuthPending = null;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: desc }));
          return;
        }
        const code = parsed.searchParams.get('code');
        const state = parsed.searchParams.get('state');
        const email = await exchangeOAuthCode(code, state);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, email }));
      } catch (e) {
        googleOAuthState = { status: 'error', error: e.message, email: null };
        googleOAuthPending = null;
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    },
    
    async handleOAuthCallback(req, res) {
      await handleOAuthCallback(req, res);
    }
  };
}

const server = http.createServer(async (req, res) => {
  const corsHeaders = getCorsHeaders(req);
  for (const [k, v] of Object.entries(corsHeaders)) res.setHeader(k, v);

  try {
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); log(req, 204); return; }

    if (req.url === '/api/configs' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getConfigs()));
      log(req, 200);
      return;
    }

    if (req.url === '/api/claude-usage' && req.method === 'GET') {
      try {
        const configs = getConfigs();
        const anthropicConfig = configs['anthropic'];
        const claudeCodeMaxConfig = configs['anthropic-claude-code'];
        
        // Try to get API key from either anthropic or claude-code-max config
        let apiKey = null;
        let configPath = null;
        
        if (claudeCodeMaxConfig && claudeCodeMaxConfig.hasKey) {
          configPath = claudeCodeMaxConfig.path;
        } else if (anthropicConfig && anthropicConfig.hasKey) {
          configPath = anthropicConfig.path;
        }
        
        if (configPath && fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf8');
          const parsed = JSON.parse(content);
          apiKey = parsed.api_key || parsed.apiKey || '';
        }
        
        if (!apiKey) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No API key configured' }));
          log(req, 401);
          return;
        }
        
        // Since Claude doesn't have a direct usage API endpoint, we'll return estimated limits
        // based on the plan type stored in the config
        const planType = parsed.plan || 'max';
        const isMax20x = planType === 'max-20x' || planType === 'max_20x';
        
        // Calculate time windows
        const now = new Date();
        const fiveHoursAgo = new Date(now.getTime() - 5 * 60 * 60 * 1000);
        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        
        // Reset times
        const next5HourReset = new Date(now.getTime() + 5 * 60 * 60 * 1000);
        const nextWeeklyReset = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        
        // Usage limits based on plan
        const limits = {
          fiveHour: isMax20x ? 900 : 225,  // Max 20x: ~900, Max 5x: ~225
          weekly: isMax20x ? 20000 : 5000  // Estimated weekly limits
        };
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          plan: isMax20x ? 'Max 20x' : 'Max 5x',
          limits,
          windows: {
            fiveHour: {
              limit: limits.fiveHour,
              resetAt: next5HourReset.toISOString(),
              description: 'Messages per 5-hour window'
            },
            weekly: {
              limit: limits.weekly,
              resetAt: nextWeeklyReset.toISOString(),
              description: 'Messages per week'
            }
          },
          note: 'Usage tracking is based on plan limits. Actual usage may vary.'
        }));
        log(req, 200);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, 500);
      }
      return;
    }

    if (req.url === '/api/save-config' && req.method === 'POST') {
      if (!(req.headers['content-type'] || '').includes('application/json')) {
        res.writeHead(415, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
        log(req, 415); return;
      }
      let body;
      try { body = JSON.parse(await readBody(req)); } catch (e) {
        const status = e.message === 'Request body too large' ? 413 : 400;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, status); return;
      }
      const err = validateSaveInput(body);
      if (err) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: err })); log(req, 400); return; }
      try {
        const configPath = saveConfig(body.providerId, body.apiKey, body.defaultModel || '');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, path: configPath }));
        log(req, 200);
      } catch (e) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: e.message })); log(req, 400); }
      return;
    }

    if (req.url === '/api/google-oauth/start' && req.method === 'POST') {
      try {
        const authUrl = await startGoogleOAuth(req);
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

    if (req.url === '/api/google-oauth/relay' && req.method === 'POST') {
      try {
        const body = JSON.parse(await readBody(req));
        const { code, state: stateParam } = body;
        if (!code || !stateParam) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing code or state' }));
          log(req, 400); return;
        }
        const email = await exchangeOAuthCode(code, stateParam);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, email }));
        log(req, 200);
      } catch (e) {
        googleOAuthState = { status: 'error', error: e.message, email: null };
        googleOAuthPending = null;
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, 400);
      }
      return;
    }

    if (req.url === '/api/google-oauth/complete' && req.method === 'POST') {
      try {
        const body = JSON.parse(await readBody(req));
        const pastedUrl = (body.url || '').trim();
        if (!pastedUrl) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'No URL provided' })); log(req, 400); return; }
        let parsed;
        try { parsed = new URL(pastedUrl); } catch (_) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid URL. Paste the full URL from the browser address bar.' }));
          log(req, 400); return;
        }
        const error = parsed.searchParams.get('error');
        if (error) {
          const desc = parsed.searchParams.get('error_description') || error;
          googleOAuthState = { status: 'error', error: desc, email: null };
          googleOAuthPending = null;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: desc }));
          log(req, 200); return;
        }
        const code = parsed.searchParams.get('code');
        const state = parsed.searchParams.get('state');
        const email = await exchangeOAuthCode(code, state);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, email }));
        log(req, 200);
      } catch (e) {
        googleOAuthState = { status: 'error', error: e.message, email: null };
        googleOAuthPending = null;
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
        log(req, 400);
      }
      return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (parsedUrl.pathname === '/oauth2callback' && req.method === 'GET') {
      try { await handleOAuthCallback(req, res); log(req, 200); } catch (e) {
        console.error('OAuth callback error:', e);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(oauthResultPage('Authentication Failed', e.message, false));
        log(req, 500);
      }
      return;
    }

    if (req.url === '/' || req.url === '/index.html') {
      fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
        if (err) { res.writeHead(500); res.end('Error loading page'); log(req, 500); return; }
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
    if (!res.headersSent) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Internal server error' })); }
    log(req, 500);
  }
});

function shutdown(signal) {
  console.log(`\n${signal} received, shutting down...`);
  server.close(() => { console.log('Server closed.'); process.exit(0); });
  setTimeout(() => { console.error('Forced shutdown after timeout.'); process.exit(1); }, 5000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (e) => console.error('Uncaught exception:', e));
process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));

function startServer(port = PORT, host = HOST) {
  server.listen(port, host, () => {
    console.log(`Agent Auth server running at http://${host}:${port}`);
    console.log(`Supported providers:`);
    Object.keys(PROVIDER_CONFIGS).forEach(p => console.log(`  - ${p}`));
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  PROVIDER_CONFIGS,
  getConfigs,
  saveConfig,
  maskKey,
  getGeminiOAuthCreds,
  getGeminiOAuthStatus,
  saveGeminiCredentials,
  startGoogleOAuth,
  exchangeOAuthCode,
  googleOAuthState: () => googleOAuthState,
  googleOAuthPending: () => googleOAuthPending,
  setGoogleOAuthState: (state) => { googleOAuthState = state; },
  setGoogleOAuthPending: (pending) => { googleOAuthPending = pending; },
  readBody,
  oauthRelayPage,
  oauthResultPage,
  handleOAuthCallback,
  encodeOAuthState,
  decodeOAuthState,
  validateSaveInput,
  fetchClaudeUsage,
  createAuthRoutes,
  startServer
};
