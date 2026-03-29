"""
mitmproxy addon that logs every HTTP(S) request URL to /output/urls.log.

Log format:
  CONNECT  host:port          — TLS tunnel opened (before DNS, always captured)
  GET/POST https://...        — decoded HTTPS or plain HTTP request
  ERROR    host:port  <msg>   — connection/DNS failure with destination info
"""

import os
from mitmproxy import http
from mitmproxy.connection import TransportProtocol

LOG_FILE = os.environ.get("URL_LOG_FILE", "/output/urls.log")


def _write(line: str) -> None:
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    print(f"[URL-LOGGER] {line}", flush=True)


def http_connect(flow: http.HTTPFlow) -> None:
    """Fires when a CONNECT tunnel is requested — before DNS resolution.

    This is the only reliable hook for capturing HTTPS destinations when
    DNS later fails (in that case the `request` hook is never reached).
    """
    host_port = f"{flow.request.host}:{flow.request.port}"
    _write(f"CONNECT  {host_port}")


def request(flow: http.HTTPFlow) -> None:
    """Fires once the full HTTP request inside the tunnel is parsed."""
    _write(f"{flow.request.method:<8} {flow.request.pretty_url}")


def error(flow: http.HTTPFlow) -> None:
    """Fires on connection errors (DNS failure, refused, timeout, …).

    flow.request may be None for very early failures, so fall back to the
    address mitmproxy was trying to reach.
    """
    if flow.request is not None:
        dest = flow.request.pretty_url or f"{flow.request.host}:{flow.request.port}"
    elif flow.server_conn is not None and flow.server_conn.address is not None:
        host, port = flow.server_conn.address
        dest = f"{host}:{port}"
    else:
        dest = "<unknown>"

    msg = flow.error.msg if flow.error else "unknown error"
    _write(f"ERROR    {dest}  [{msg}]")
