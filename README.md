# Agent Auth 🤖

Universal OAuth Authenticator for AI Agents - a buildless web application using WebJSX and Ripple-UI.

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

Then open http://localhost:3000 in your browser.

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

## Tech Stack

- **WebJSX** - Minimal JSX runtime for Web Components
- **Ripple-UI** - Tailwind CSS component library
- **Node.js** - Simple HTTP server for file operations
