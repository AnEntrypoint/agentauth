const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 8765;
const HOST = process.env.HOST || '127.0.0.1';
const MAX_BODY = 1024 * 1024;
const ALLOWED_ORIGINS = new Set([
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`
]);

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

function getConfigs() {
  const configs = {};

  for (const [providerId, config] of Object.entries(PROVIDER_CONFIGS)) {
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
  if (ALLOWED_ORIGINS.has(origin)) {
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
