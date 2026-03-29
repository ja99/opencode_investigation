# opencode-ai Network Traffic Investigation

Investigate what external services [opencode-ai](https://github.com/opencode-ai/opencode) contacts at runtime, detect supply chain risks in its runtime dependencies, and monitor each new release automatically.

## Motivation

When using opencode with an external LLM provider (e.g. OpenRouter), you want assurance that:
- Workspace content isn't sent to unexpected services
- Telemetry can be fully disabled
- Sharing can be fully disabled
- No hidden phone-home behavior exists
- Runtime npm dependencies haven't been tampered with (supply chain attacks)

## How It Works

A Docker container (Ubuntu 24.04) runs opencode-ai with **all HTTP/HTTPS traffic routed through mitmproxy**. After each run, an SBOM is generated from the captured traffic and a full safety report is produced.

```
┌─────────────────────────────────────────────┐
│  Docker Container (Ubuntu 24.04)            │
│                                             │
│  opencode-ai ──► mitmdump ──► internet      │
│       │              │                      │
│       │         url_logger.py               │
│       │              │                      │
│       ▼              ▼                      │
│  LLM response   /output/urls.log            │
└────────────────────────┬────────────────────┘
                         │ (volume mount)
                         ▼
              output/v{version}/
                  urls.log
                  mitmdump.log
                  sbom.json          ◄── sbom_generator.py
                  report.md          ◄── report_generator.py
```

### Log format

`url_logger.py` uses three mitmproxy hooks to ensure destinations are captured even when connections fail:

| Prefix | Hook | When logged |
|---|---|---|
| `CONNECT  host:port` | `http_connect` | TLS tunnel opened — fires **before DNS resolution** |
| `METHOD   https://…` | `request` | Full request decoded inside the tunnel |
| `ERROR    host:port  [msg]` | `error` | Connection/DNS/TLS failure with error detail |

For a successful HTTPS request you see both a `CONNECT` and a `METHOD` line. For a DNS failure you see `CONNECT` + `ERROR`, which still tells you which host was attempted.

## Supply Chain Monitoring (SBOM)

Every run generates a Software Bill of Materials from the runtime npm packages opencode installs. This detects [supply chain attacks like the Cline/clinejection incident](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/), where a malicious `postinstall` script was injected into a tampered npm package.

For each runtime npm package, `sbom_generator.py` fetches live registry metadata and checks:

| Check | Severity | What it catches |
|---|---|---|
| `postinstall` / `preinstall` / `install` script present | 🚨 ALERT | Direct Cline-style attack vector |
| Suspicious script content (`npm install -g`, `curl \|`, `eval`, …) | 🚨 ALERT | Malicious payload in lifecycle script |
| Known CVE (CRITICAL or HIGH) | 🚨 ALERT | Vulnerability with known exploit risk |
| Known CVE (MODERATE or LOW) | ⚠️ WARN | Lower-severity known vulnerability |
| Package not in baseline | ⚠️ WARN | New undeclared dependency added |
| Version changed vs baseline | ⚠️ WARN | Possible tampered update |
| Integrity hash changed vs baseline | 🚨 ALERT | Package contents modified |
| npm registry unreachable | ⚠️ WARN | Can't verify — blind spot |
| Binary from untrusted CDN | ⚠️ WARN | Unexpected binary source |

CVE data comes from the **[OSV API](https://osv.dev)** (Google Open Source Vulnerabilities). No API key required. Covers npm and crates.io (for binaries like ripgrep). Each CVE links back to the full OSV advisory.

The SBOM is saved as `output/v{version}/sbom.json`. A persistent baseline at `output/sbom_baseline.json` is used to diff across versions.

## Automated Daily Monitoring

`orchestrator.py` ties everything together for continuous monitoring:

```bash
# Checks npm, runs investigation only if new version found
uv run python orchestrator.py

# Force a re-run regardless of version
uv run python orchestrator.py --force

# After reviewing a clean report, advance the SBOM baseline
uv run python orchestrator.py --update-baseline
```

**To run daily**, add this to your crontab (`crontab -e`):

```
17 8 * * * cd /path/to/opencode_investigation && uv run python orchestrator.py >> output/cron.log 2>&1
```

**Full automated flow:**
1. Check `registry.npmjs.org/opencode-ai/latest` for new version
2. Skip if version matches `state/last_version.txt`
3. `docker build` + `docker run` to capture network traffic
4. `sbom_generator.py` — fetch npm metadata, check scripts, diff vs persistent baseline
5. `report_generator.py` — generate `output/v{version}/report.md`
6. `output/latest` symlink updated to the new version directory
7. Exit code 1 if any ALERT findings (CI-friendly)

## Quick Start

### 1. Configure

Copy `api.env.example` to `api.env` and fill in your provider details:

```env
MY_LLM_BASE_URL=https://openrouter.ai/api/v1
MY_LLM_API_KEY=sk-or-v1-your-key-here
MY_LLM_MODEL_NAME=google/gemini-2.0-flash-001
```

### 2. Run (automated)

```bash
uv run python orchestrator.py
```

This builds the Docker image, runs the investigation, generates the SBOM and report, and saves everything to `output/v{version}/`.

### 3. Read the report

```bash
cat output/latest/report.md
```

---

### Manual Docker workflow

If you want to run the Docker container directly:

```bash
# Build
docker build \
  --build-arg MY_LLM_BASE_URL="$(grep MY_LLM_BASE_URL api.env | cut -d= -f2-)" \
  --build-arg MY_LLM_API_KEY="$(grep MY_LLM_API_KEY api.env | cut -d= -f2-)" \
  --build-arg MY_LLM_MODEL_NAME="$(grep MY_LLM_MODEL_NAME api.env | cut -d= -f2-)" \
  -t opencode-investigation .

# Run
mkdir -p output
docker run --rm -v "$(pwd)/output:/output" opencode-investigation
```

Then analyze manually:

```bash
# All attempted destinations
grep -E '^(CONNECT|GET|POST|PUT|DELETE|ERROR)' output/urls.log | sort -u

# Run SBOM + report against a specific output dir
URL_LOG_FILE=output/urls.log RUN_OUTPUT_DIR=output uv run python sbom_generator.py
OPENCODE_VERSION=x.y.z RUN_OUTPUT_DIR=output uv run python report_generator.py
```

## Files

| File | Description |
|---|---|
| `orchestrator.py` | Daily driver: version check → Docker → SBOM → report |
| `report_generator.py` | Generates `report.md` from `urls.log` + `sbom.json` |
| `sbom_generator.py` | SBOM from captured traffic; supply chain check vs baseline |
| `url_logger.py` | mitmproxy addon — logs CONNECT tunnels, requests, and errors |
| `run_investigation.sh` | Docker entrypoint: starts proxy, runs prompts, calls SBOM |
| `vt_scanner.py` | Optional: scan URLs and binaries with VirusTotal |
| `Dockerfile` | Ubuntu 24.04 + Node.js 20 + mitmproxy + opencode-ai |
| `openrouter.json` | opencode config (copied as `opencode.json` into the container) |
| `api.env` | LLM provider credentials (gitignored) |
| `api.env.example` | Template for `api.env` |
| `state/last_version.txt` | Last investigated version (skip unchanged releases) |
| `output/sbom_baseline.json` | Persistent SBOM baseline for cross-version diffing |
| `output/latest/` | Symlink to the most recent versioned output directory |
| `output/v{version}/urls.log` | Raw captured URLs for that version |
| `output/v{version}/mitmdump.log` | Raw mitmdump output for that version |
| `output/v{version}/sbom.json` | SBOM for that version |
| `output/v{version}/report.md` | Auto-generated safety report for that version |
| `report.md` | Manual analysis report (historical, pre-automation) |

## Results (TL;DR)

Tested on v1.3.5 with `share: "disabled"`, `autoupdate: false`, `openTelemetry: false`, and `disabled_providers: ["opencode"]`:

- ✅ No telemetry or analytics endpoints detected
- ✅ No workspace content sent to unexpected services
- ✅ No opencode.ai servers contacted
- ✅ No lifecycle scripts (postinstall/preinstall/install) in any runtime npm package
- ✅ All npm packages carry valid `dist.integrity` hashes
- ✅ No CVEs found in runtime dependencies (checked via OSV)
- ⚠️ Runtime npm package downloads on every cold start (`@opencode-ai/plugin`, `@opencode-ai/sdk`, `zod`)
- ⚠️ Third-party model catalog fetch from `models.dev` (once per prompt)
- ⚠️ ripgrep binary download from GitHub on first run

See [report.md](report.md) for the full historical analysis.
