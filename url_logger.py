"""
mitmproxy addon that logs every HTTP(S) request URL to /output/urls.log
"""

import os
from mitmproxy import http

LOG_FILE = os.environ.get("URL_LOG_FILE", "/output/urls.log")


def request(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    method = flow.request.method
    line = f"{method} {url}\n"

    with open(LOG_FILE, "a") as f:
        f.write(line)

    # Also print to stdout for live visibility
    print(f"[URL-LOGGER] {method} {url}", flush=True)
