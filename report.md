# OpenCode Network Traffic Investigation — Report

**Date:** 2026-02-23  
**Tool:** opencode-ai (npm `opencode-ai`, v1.2.10)  
**Method:** mitmproxy interception inside Docker (Ubuntu 24.04)

---

## Setup

| Parameter | Value |
|---|---|
| Container OS | Ubuntu 24.04 |
| Node.js | v20 (NodeSource) |
| Interception | `mitmdump` on port 8080, all HTTP/HTTPS proxied |
| LLM Provider | OpenRouter (`openrouter.ai/api/v1`) |
| Model | `google/gemini-2.0-flash-001` |
| Config flags | `share: "disabled"`, `autoupdate: false`, `openTelemetry: false`, `disabled_providers: ["opencode"]` |
| Prompt tested | `"What is 2+2? Reply with just the number."` |

## Summary

| Metric | Value |
|---|---|
| Total requests logged | **43** |
| Unique request signatures | **35** |
| Unique domains contacted | **5** |

## Domains Contacted

| # | Domain | Purpose | Concern? |
|---|---|---|---|
| 1 | `openrouter.ai` | Configured LLM API (`POST /api/v1/chat/completions`) | ✅ Expected |
| 2 | `registry.npmjs.org` | Runtime npm package downloads (provider SDK, plugins, auth) | ⚠️ See below |
| 3 | `models.dev` | Third-party model metadata catalog (`GET /api.json`) | ⚠️ See below |
| 4 | `github.com` | ripgrep binary download | ⚠️ See below |
| 5 | `release-assets.githubusercontent.com` | GitHub CDN redirect for ripgrep | ⚠️ See below |

---

## Detailed Analysis

### 1. `openrouter.ai` — LLM API (expected)

Requests were `POST https://openrouter.ai/api/v1/chat/completions`. This is the configured provider endpoint — completely expected. In version 1.2.10, the behavior is more stable than earlier versions, with no excessive retries observed on successful responses.

### 2. `registry.npmjs.org` — Runtime npm Installs

opencode dynamically installs provider SDKs at **runtime** (not just install time). On first startup it fetched **16 packages**:

| Package | Purpose |
|---|---|
| `opencode-anthropic-auth` | Anthropic OAuth (fetched even though Anthropic is not configured) |
| `@openauthjs/openauth` | OpenAuth library |
| `@opencode-ai/plugin` | opencode plugin system |
| `@opencode-ai/sdk` | opencode SDK |
| `arctic` | OAuth 2.0 library |
| `hono` | HTTP framework |
| `jose` | JWT/JWS/JWE library |
| `aws4fetch` | AWS Signature V4 fetch |
| `@oslojs/jwt`, `@oslojs/crypto`, `@oslojs/encoding`, `@oslojs/asn1`, `@oslojs/binary` | Crypto utilities |
| `@standard-schema/spec` | Schema specification |
| `zod` | Schema validation |

**Note:** These are fetched on every cold start if not cached. This includes Anthropic auth packages even when only OpenRouter is configured.

### 3. `models.dev` — Model Catalog

`GET https://models.dev/api.json` fetches a JSON catalog of AI models. This is a third-party service used to populate model metadata/capabilities.

### 4. `github.com` + `release-assets.githubusercontent.com` — ripgrep

opencode downloads `ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz` from GitHub at runtime. ripgrep powers its file search tool. This is a runtime download, not an install-time dependency.

---

## Key Findings

### ✅ What's Respected

- **No telemetry endpoints detected** — `openTelemetry: false` is honored
- **No sharing endpoints detected** — `share: "disabled"` is honored
- **No opencode.ai servers contacted** — `disabled_providers: ["opencode"]` is honored
- **No workspace content sent to unexpected destinations**

### ⚠️ What to Be Aware Of

- opencode makes **runtime network calls beyond your LLM API** to npm, GitHub, and models.dev
- These don't transmit workspace content, but they leak metadata (IP address, timing, user-agent)
- Anthropic auth packages are fetched even when you only use OpenRouter
- Version 1.2.10 is significantly more stable in terms of API request volume than earlier versions (v1.1.52)

---

## Verdict

| Question | Answer |
|---|---|
| Does it send workspace content to unexpected services? | **No** |
| Does it respect `openTelemetry: false`? | **Yes** |
| Does it respect `share: disabled`? | **Yes** |
| Does it contact services beyond OpenRouter? | **Yes** — npm, GitHub, models.dev |
| Does it contact `opencode.ai` servers? | **No** |

---

## Raw Data

- `output/urls.log` — Full log of all intercepted requests
- `output/mitmdump.log` — Raw mitmdump output
