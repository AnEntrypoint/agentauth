# Agent Auth

Universal Credential Manager for AI Agents - a buildless web application using WebJSX and Ripple-UI.

## Supported Providers

- **Claude Code / Anthropic** - Anthropic API for Claude AI
- **OpenAI** - GPT models via OpenAI
- **Google Gemini** - Gemini CLI and Gemini API
- **OpenRouter** - Unified access to multiple LLM providers
- **GitHub Models** - GitHub Copilot and Models
- **Azure OpenAI** - Microsoft Azure OpenAI Service
- **Claude Code Max** - Claude Code with Max plan
- **OpenCode** - OpenCode CLI authentication
- **ProxyPilot** - ProxyPilot providers

## Quick Start

```bash
npm start
```

Then open http://localhost:8765 in your browser.

## Usage

1. Click "Connect" on a provider card
2. Enter your API key or OAuth token
3. Click "Get [Provider] credentials" to obtain credentials if needed
4. Click "Save" to store the configuration
5. Use "Set Model" to choose your default model

## Configuration

Configs are stored in your home directory:
- `~/.claude.json` - Claude Code
- `~/.openai.json` - OpenAI
- `~/.gemini.json` - Google Gemini
- `~/.openrouter.json` - OpenRouter
- `~/.github.json` - GitHub
- `~/.azure.json` - Azure OpenAI
- `~/.claude/max.json` - Claude Code Max
- `~/.opencode/config.json` - OpenCode
- `~/.proxypilot/config.json` - ProxyPilot

## Security

- Server binds to localhost (127.0.0.1) by default
- CORS restricted to localhost origins only
- API keys are masked in GET responses (only last 4 characters shown)
- Config files are written with 0600 permissions (owner-only)
- Request body size limited to 1MB
- All inputs validated before processing

## Tech Stack

- **WebJSX** - Minimal JSX runtime for Web Components
- **Ripple-UI** - Tailwind CSS component library
- **Node.js** - Simple HTTP server for file operations
