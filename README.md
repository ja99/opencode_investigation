# opencode-ai Network Traffic Investigation

Investigate what external services [opencode-ai](https://github.com/opencode-ai/opencode) contacts at runtime, and whether it respects privacy-related config settings.

## Motivation

When using opencode with an external LLM provider (e.g. OpenRouter), you want assurance that:
- Workspace content isn't sent to unexpected services
- Telemetry can be fully disabled
- Sharing can be fully disabled
- No hidden phone-home behavior exists

## How It Works

A Docker container (Ubuntu 24.04) runs opencode-ai with **all HTTP/HTTPS traffic routed through mitmproxy**. Every request URL is logged to `output/urls.log`.

```
┌─────────────────────────────────────────┐
│  Docker Container (Ubuntu 24.04)        │
│                                         │
│  opencode-ai ──► mitmdump ──► internet  │
│       │              │                  │
│       │         url_logger.py           │
│       │              │                  │
│       ▼              ▼                  │
│  LLM response   /output/urls.log       │
└─────────────────────────────────────────┘
```

## Quick Start

### 1. Configure

Copy `api.env.example` to `api.env` and fill in your provider details:

```env
MY_LLM_BASE_URL=https://openrouter.ai/api/v1
MY_LLM_API_KEY=sk-or-v1-your-key-here
MY_LLM_MODEL_NAME=google/gemini-2.0-flash-001
```

Edit `openrouter.json` if you want to change the opencode config (provider, disabled features, etc.).

### 2. Build

```bash
docker build \
  --build-arg MY_LLM_BASE_URL="$(grep MY_LLM_BASE_URL api.env | cut -d= -f2-)" \
  --build-arg MY_LLM_API_KEY="$(grep MY_LLM_API_KEY api.env | cut -d= -f2-)" \
  --build-arg MY_LLM_MODEL_NAME="$(grep MY_LLM_MODEL_NAME api.env | cut -d= -f2-)" \
  -t opencode-investigation .
```

### 3. Run

```bash
mkdir -p output
docker run --rm -v "$(pwd)/output:/output" opencode-investigation
```

### 4. Analyze

```bash
# Unique URLs contacted
sort -u output/urls.log

# Unique domains
awk '{print $2}' output/urls.log | sed 's|https\?://||' | sed 's|/.*||' | sort -u
```

## Files

| File | Description |
|---|---|
| `Dockerfile` | Ubuntu 24.04 + Node.js 20 + mitmproxy + opencode-ai |
| `openrouter.json` | opencode config (copied as `opencode.json` into container) |
| `api.env` | Environment variables for the LLM provider |
| `api.env.example` | Template for `api.env` |
| `url_logger.py` | mitmproxy addon that logs every request URL |
| `run_investigation.sh` | Entrypoint: starts proxy, runs prompts, reports results |
| `report.md` | Full analysis of captured traffic |
| `output/urls.log` | Raw captured URLs (after running) |
| `output/mitmdump.log` | Raw mitmdump output (after running) |

## Results (TL;DR)

With `share: "disabled"`, `autoupdate: false`, `openTelemetry: false`, and `disabled_providers: ["opencode"]`:

- ✅ No telemetry or analytics endpoints detected
- ✅ No workspace content sent to unexpected services
- ✅ No opencode.ai servers contacted
- ⚠️ Runtime npm package downloads on every cold start (including unused Anthropic auth)
- ⚠️ Third-party model catalog fetch from `models.dev`
- ⚠️ ripgrep binary download from GitHub

See [report.md](report.md) for the full analysis.
