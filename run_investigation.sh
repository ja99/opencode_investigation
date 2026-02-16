#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="/output"
URL_LOG="$OUTPUT_DIR/urls.log"

mkdir -p "$OUTPUT_DIR"
: > "$URL_LOG"  # truncate

echo "=== Starting mitmproxy (mitmdump) on port 8080 ==="
mitmdump --listen-port 8080 \
         --set ssl_insecure=true \
         -s /app/url_logger.py \
         > "$OUTPUT_DIR/mitmdump.log" 2>&1 &
MITM_PID=$!

# Wait for mitmproxy to be ready
sleep 3

# Configure proxy for all HTTP(S) traffic
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
export http_proxy="http://127.0.0.1:8080"
export https_proxy="http://127.0.0.1:8080"

# Trust the mitmproxy CA for Node.js
export NODE_EXTRA_CA_CERTS="/root/.mitmproxy/mitmproxy-ca-cert.pem"
# Fallback: disable strict TLS checking for Node
export NODE_TLS_REJECT_UNAUTHORIZED=0

echo ""
echo "=== Proxy configured. Running opencode prompts... ==="
echo ""

# ------ Prompt 1: Simple math ------
echo "--- Prompt 1: What is 2+2? ---"
opencode run "What is 2+2? Reply with just the number." 2>&1 || echo "[WARN] opencode exited with non-zero"
echo ""

# ------ Prompt 2: Code question ------
echo "--- Prompt 2: Write a hello world ---"
opencode run "Write a Python hello world script. Keep it short." 2>&1 || echo "[WARN] opencode exited with non-zero"
echo ""

# ------ Prompt 3: File inspection ------
echo "--- Prompt 3: List files ---"
opencode run "List the files in the current directory." 2>&1 || echo "[WARN] opencode exited with non-zero"
echo ""

echo "=== All prompts done. Stopping mitmproxy... ==="
kill "$MITM_PID" 2>/dev/null || true
wait "$MITM_PID" 2>/dev/null || true

echo ""
echo "======================================"
echo "  CAPTURED URLS (unique, sorted)"
echo "======================================"
if [ -s "$URL_LOG" ]; then
    sort -u "$URL_LOG"
    echo ""
    echo "Total unique URLs: $(sort -u "$URL_LOG" | wc -l)"
    echo "Total requests:    $(wc -l < "$URL_LOG")"
else
    echo "(no URLs captured)"
fi
echo ""
echo "Full URL log:     $URL_LOG"
echo "mitmdump log:     $OUTPUT_DIR/mitmdump.log"
echo "======================================"
