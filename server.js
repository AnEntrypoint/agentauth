const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 8765;

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

function getConfigs() {
  const configs = {};
  
  for (const [providerId, config] of Object.entries(PROVIDER_CONFIGS)) {
    for (const configPath of config.configPaths) {
      try {
        if (fs.existsSync(configPath)) {
          const content = fs.readFileSync(configPath, 'utf8');
          const parsed = JSON.parse(content);
          configs[providerId] = {
            apiKey: parsed.api_key || parsed.apiKey || parsed.github_token || '',
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
  
  let configPath = config.configPaths[0];
  const configDir = path.dirname(configPath);
  
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
  
  const configData = config.configFormat(apiKey, defaultModel);
  fs.writeFileSync(configPath, JSON.stringify(configData, null, 2));
  
  return configPath;
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  if (req.url === '/api/configs' && req.method === 'GET') {
    const configs = getConfigs();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(configs));
    return;
  }
  
  if (req.url === '/api/save-config' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { providerId, apiKey, defaultModel } = JSON.parse(body);
        const configPath = saveConfig(providerId, apiKey, defaultModel);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, path: configPath }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }
  
  if (req.url === '/' || req.url === '/index.html') {
    const htmlPath = path.join(__dirname, 'index.html');
    fs.readFile(htmlPath, (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading index.html');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }
  
  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`🤖 Agent Auth server running at http://localhost:${PORT}`);
  console.log(`\nSupported providers:`);
  Object.keys(PROVIDER_CONFIGS).forEach(p => console.log(`  - ${p}`));
});
