FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System deps ──────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    gnupg \
    python3 \
    python3-pip \
    pipx \
    git \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20 via NodeSource ────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Install mitmproxy via pipx ───────────────────────────────────
RUN pipx install mitmproxy && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

# Pre-generate mitmproxy CA certificate
RUN mitmdump --listen-port 0 &  MITM_PID=$! && sleep 2 && kill $MITM_PID 2>/dev/null || true

# Trust mitmproxy CA system-wide (for curl, etc.)
RUN cp /root/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt \
    && update-ca-certificates

# ── Install opencode-ai globally ─────────────────────────────────
RUN npm install -g opencode-ai

# ── Set up workspace ─────────────────────────────────────────────
WORKDIR /workspace

# Copy the sample project files
COPY main.py /workspace/main.py

# Copy opencode config as project-level config
COPY openrouter.json /workspace/opencode.json

# Copy mitmproxy logger addon
COPY url_logger.py /app/url_logger.py

# Copy entrypoint script
COPY run_investigation.sh /app/run_investigation.sh
RUN chmod +x /app/run_investigation.sh

# ── Environment variables from api.env ───────────────────────────
# These are read by the opencode config via {env:MY_LLM_*} placeholders
ARG MY_LLM_BASE_URL
ARG MY_LLM_API_KEY
ARG MY_LLM_MODEL_NAME
ENV MY_LLM_BASE_URL=${MY_LLM_BASE_URL}
ENV MY_LLM_API_KEY=${MY_LLM_API_KEY}
ENV MY_LLM_MODEL_NAME=${MY_LLM_MODEL_NAME}

# Tell Node.js to trust the mitmproxy CA
ENV NODE_EXTRA_CA_CERTS=/root/.mitmproxy/mitmproxy-ca-cert.pem

ENTRYPOINT ["/app/run_investigation.sh"]
