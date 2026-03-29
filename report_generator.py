#!/usr/bin/env python3
"""Generate a markdown safety report from investigation outputs.

Reads urls.log and sbom.json from a run output directory and produces
a structured, human-readable report.

Environment variables:
    OPENCODE_VERSION   - the opencode-ai version being reported on
    RUN_OUTPUT_DIR     - directory containing urls.log, sbom.json
    REPORT_OUTPUT      - path to write the report (default: RUN_OUTPUT_DIR/report.md)
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VERSION = os.environ.get("OPENCODE_VERSION", "unknown")
RUN_OUTPUT_DIR = Path(os.environ.get("RUN_OUTPUT_DIR", "./output"))
REPORT_OUTPUT = Path(os.environ.get("REPORT_OUTPUT", str(RUN_OUTPUT_DIR / "report.md")))

# Domain classification: (purpose, risk_level)
# risk_level: "ok" | "warn" | "alert"
KNOWN_DOMAINS: dict[str, tuple[str, str]] = {
    "openrouter.ai":                       ("LLM API (configured provider)", "ok"),
    "api.openai.com":                      ("LLM API (configured provider)", "ok"),
    "api.anthropic.com":                   ("LLM API (configured provider)", "ok"),
    "api.groq.com":                        ("LLM API (configured provider)", "ok"),
    "registry.npmjs.org":                  ("Runtime npm package installs", "warn"),
    "github.com":                          ("Binary/release download", "warn"),
    "release-assets.githubusercontent.com": ("GitHub CDN (release assets)", "warn"),
    "objects.githubusercontent.com":       ("GitHub CDN (release assets)", "warn"),
    "models.dev":                          ("Third-party model metadata catalog", "warn"),
    "opencode.ai":                         ("opencode.ai servers — unexpected", "alert"),
    "telemetry.opencode.ai":               ("Telemetry endpoint — unexpected", "alert"),
}

RISK_EMOJI: dict[str, str] = {"ok": "✅", "warn": "⚠️", "alert": "🚨"}


# ── Parsing helpers ───────────────────────────────────────────────────────────


def parse_urls_log(log_path: Path) -> list[str]:
    if not log_path.exists():
        return []
    return [l.strip() for l in log_path.read_text().splitlines() if l.strip()]


def extract_domain(entry: str) -> str | None:
    """Extract hostname from a log line (GET/POST/CONNECT/ERROR)."""
    parts = entry.split(None, 1)
    if len(parts) < 2:
        return None
    _, target = parts
    if "://" in target:
        return urlparse(target).hostname or None
    # CONNECT host:port
    return target.split(":")[0] if ":" in target else target


def classify_domain(domain: str) -> tuple[str, str]:
    """Returns (purpose, risk_level) for a domain."""
    return KNOWN_DOMAINS.get(domain, ("Unknown / unclassified", "alert"))


def load_sbom(sbom_path: Path) -> dict:
    if not sbom_path.exists():
        return {}
    try:
        return json.loads(sbom_path.read_text())
    except Exception:
        return {}


# ── Report sections ───────────────────────────────────────────────────────────


def _verdict_block(alerts: list[dict], warns: list[dict]) -> tuple[str, str]:
    """Returns (one-line verdict string, short label)."""
    if alerts:
        return f"🚨 **UNSAFE** — {len(alerts)} alert(s) require immediate review", "UNSAFE"
    if warns:
        return f"⚠️ **REVIEW NEEDED** — {len(warns)} warning(s) detected", "NEEDS REVIEW"
    return "✅ **SAFE** — No issues detected", "SAFE"


def section_header(log_lines: list[str], domains: dict[str, str]) -> list[str]:
    """Summary table of domains contacted."""
    lines = [
        "## Network Traffic",
        "",
        f"Opencode contacted **{len(domains)} unique domain(s)** during the test session.",
        "",
        "| Domain | Purpose | Status |",
        "|--------|---------|--------|",
    ]
    for domain in sorted(domains):
        purpose, risk = classify_domain(domain)
        emoji = RISK_EMOJI[risk]
        lines.append(f"| `{domain}` | {purpose} | {emoji} |")

    get_c = sum(1 for l in log_lines if l.startswith("GET "))
    post_c = sum(1 for l in log_lines if l.startswith("POST "))
    con_c = sum(1 for l in log_lines if l.startswith("CONNECT "))
    err_c = sum(1 for l in log_lines if l.startswith("ERROR "))
    lines += [
        "",
        f"**Requests**: {len(log_lines)} total — {get_c} GET, {post_c} POST, "
        f"{con_c} CONNECT tunnels, {err_c} errors",
    ]
    return lines


def _cve_cell(cves: list[dict]) -> str:
    """Render a compact CVE summary for a table cell."""
    if not cves:
        return "✅ none"
    by_sev: dict[str, int] = {}
    for cve in cves:
        sev = cve.get("severity") or "UNKNOWN"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    critical = by_sev.get("CRITICAL", 0) + by_sev.get("HIGH", 0)
    label = ", ".join(f"{v} {k}" for k, v in by_sev.items())
    icon = "🚨" if critical else "⚠️"
    return f"{icon} {len(cves)} CVE(s): {label}"


def section_sbom(sbom: dict) -> list[str]:
    components: list[dict] = sbom.get("components", [])
    npm = [c for c in components if c.get("type") == "npm"]
    binaries = [c for c in components if c.get("type") == "binary"]

    if not components:
        return ["## SBOM — Runtime Dependencies", "", "_No components detected._"]

    lines = ["## SBOM — Runtime Dependencies", ""]

    if npm:
        lines += [
            "### npm Packages (installed at runtime)",
            "",
            "| Package | Version | Integrity | Lifecycle Scripts | CVEs |",
            "|---------|---------|-----------|-------------------|------|",
        ]
        for c in npm:
            integ = c.get("integrity") or ""
            integ_str = f"✅ `{integ[:16]}…`" if integ else "❌ missing"
            scripts: dict = c.get("scripts", {})
            script_str = "🚨 " + ", ".join(f"`{k}`" for k in scripts) if scripts else "✅ none"
            cve_str = _cve_cell(c.get("cves", []))
            lines.append(f"| `{c['name']}` | `{c['version']}` | {integ_str} | {script_str} | {cve_str} |")

    if binaries:
        lines += [
            "",
            "### Binary Downloads",
            "",
            "| Name | Version | Source | Trusted? | CVEs |",
            "|------|---------|--------|----------|------|",
        ]
        for c in binaries:
            host = urlparse(c.get("source_url", "")).hostname or "?"
            trusted_hosts = {"github.com", "release-assets.githubusercontent.com",
                             "objects.githubusercontent.com"}
            trusted = "✅" if host in trusted_hosts else "🚨"
            cve_str = _cve_cell(c.get("cves", []))
            lines.append(f"| `{c['name']}` | `{c.get('version', '?')}` | `{host}` | {trusted} | {cve_str} |")

    return lines


def section_checks(sbom: dict, log_lines: list[str], domains: dict[str, str]) -> list[str]:
    findings: list[dict] = sbom.get("findings", [])
    diff: list[dict] | None = sbom.get("diff")

    def _has(check: str) -> bool:
        return any(f["check"] == check for f in findings if f["severity"] in ("ALERT", "WARN"))

    def _alert(check: str) -> bool:
        return any(f["check"] == check and f["severity"] == "ALERT" for f in findings)

    postinstall_alert = any(
        f["severity"] == "ALERT" and "script" in f["check"] for f in findings
    )
    integrity_warn = _has("missing_integrity")
    registry_fail = _has("registry_fetch_failed")
    unexpected_cdn = _has("unexpected_binary_cdn")

    alert_domains = [d for d in domains if classify_domain(d)[1] == "alert"]
    post_urls = [l.split(None, 1)[1] for l in log_lines if l.startswith("POST ")]
    known_llm = {"openrouter.ai", "api.openai.com", "api.anthropic.com", "api.groq.com"}
    unexpected_posts = [u for u in post_urls if urlparse(u).hostname not in known_llm]

    if diff is None:
        baseline_str = "ℹ️ First run — baseline saved"
    elif diff:
        baseline_str = f"⚠️ {len(diff)} change(s) vs baseline"
    else:
        baseline_str = "✅ No changes vs baseline"

    # CVE summary across all components
    all_cves: list[dict] = []
    for comp in sbom.get("components", []):
        all_cves.extend(comp.get("cves", []))
    cve_alerts = [c for c in all_cves if c.get("severity") in ("CRITICAL", "HIGH")]
    if not all_cves:
        cve_str = "✅ None found"
    elif cve_alerts:
        cve_str = f"🚨 **{len(all_cves)} CVE(s)** — {len(cve_alerts)} CRITICAL/HIGH"
    else:
        cve_str = f"⚠️ {len(all_cves)} CVE(s) — no CRITICAL/HIGH"

    lines = [
        "## Supply Chain Security Checks",
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| Lifecycle scripts (postinstall / preinstall / install) | {'🚨 **ALERT** — see Findings' if postinstall_alert else '✅ None found'} |",
        f"| Known CVEs in runtime dependencies | {cve_str} |",
        f"| npm integrity hashes present | {'⚠️ Some missing' if integrity_warn else '✅ All present'} |",
        f"| npm registry reachable | {'⚠️ Some failed' if registry_fail else '✅ Yes'} |",
        f"| Binary sources trusted | {'🚨 **ALERT** — unexpected CDN' if unexpected_cdn else '✅ Yes'} |",
        f"| Baseline comparison | {baseline_str} |",
        "",
        "## Privacy Checks",
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| No opencode.ai / telemetry endpoints | {'🚨 **ALERT** — ' + ', '.join(alert_domains) if alert_domains else '✅ Pass'} |",
        f"| No unexpected POST requests | {'⚠️ ' + str(len(unexpected_posts)) + ' unexpected POST(s)' if unexpected_posts else '✅ Pass'} |",
    ]

    if unexpected_posts:
        lines.append("")
        lines.append("  Unexpected POST targets:")
        for u in unexpected_posts:
            lines.append(f"  - `{u}`")

    return lines


def section_findings(findings: list[dict]) -> list[str]:
    alerts = [f for f in findings if f["severity"] == "ALERT"]
    warns = [f for f in findings if f["severity"] == "WARN"]
    notable = alerts + warns
    if not notable:
        return []

    lines = ["## Findings Detail", ""]
    for f in notable:
        icon = "🚨" if f["severity"] == "ALERT" else "⚠️"
        lines += [
            f"### {icon} `{f['check']}` — {f['component']}",
            "",
            f"{f['detail']}",
            "",
        ]
    return lines


def section_cves(components: list[dict]) -> list[str]:
    """Detailed CVE listing per component."""
    entries: list[tuple[str, dict]] = []
    for comp in components:
        label = f"{comp['name']}@{comp['version']}" if comp.get("type") == "npm" else comp["name"]
        for cve in comp.get("cves", []):
            entries.append((label, cve))

    if not entries:
        return []

    SEV_ICON = {"CRITICAL": "🚨", "HIGH": "🚨", "MODERATE": "⚠️", "MEDIUM": "⚠️", "LOW": "ℹ️"}
    lines = ["## CVE Details", ""]
    for pkg, cve in entries:
        sev = cve.get("severity") or "UNKNOWN"
        icon = SEV_ICON.get(sev, "❓")
        cve_id = cve.get("id", "")
        aliases = cve.get("aliases", [])
        alias_str = f" _(also: {', '.join(aliases[:3])})_" if aliases else ""
        lines += [
            f"### {icon} {cve_id}{alias_str} — `{pkg}`",
            "",
            f"**Severity**: {sev}  ",
            f"**Summary**: {cve.get('summary', '—')}  ",
            f"**Details**: {cve.get('details_url', '—')}",
            "",
        ]
    return lines


def section_baseline_diff(diff: list[dict] | None) -> list[str]:
    if not diff:
        return []

    lines = ["## Changes from Previous Baseline", ""]
    change_labels = {
        "new_package": ("⚠️", "New package"),
        "version_change": ("ℹ️", "Version changed"),
        "script_change": ("🚨", "Lifecycle scripts changed"),
        "integrity_change": ("🚨", "Integrity hash changed"),
        "removed_package": ("ℹ️", "Package removed"),
    }
    for entry in diff:
        icon, label = change_labels.get(entry["change"], ("❓", entry["change"]))
        before = f"`{entry['before']}`" if entry["before"] else "—"
        after = f"`{entry['after']}`" if entry["after"] else "—"
        lines.append(f"- {icon} **{label}**: `{entry['component']}` (before: {before} → after: {after})")
    return lines


def section_raw_urls(log_lines: list[str]) -> list[str]:
    unique = sorted(set(log_lines))
    lines = [
        "## Raw Captured Requests",
        "",
        "```",
    ]
    lines += unique
    lines += ["```"]
    return lines


# ── Top-level generator ───────────────────────────────────────────────────────


def generate_report(version: str, run_output_dir: Path) -> str:
    urls_log = run_output_dir / "urls.log"
    sbom_path = run_output_dir / "sbom.json"

    log_lines = parse_urls_log(urls_log)
    sbom = load_sbom(sbom_path)

    # Build domain → risk map
    domains: dict[str, str] = {}
    for line in log_lines:
        d = extract_domain(line)
        if d:
            _, risk = classify_domain(d)
            # Keep highest risk seen for this domain
            existing = domains.get(d, "ok")
            priority = {"ok": 0, "warn": 1, "alert": 2}
            if priority[risk] >= priority[existing]:
                domains[d] = risk

    findings: list[dict] = sbom.get("findings", [])
    diff: list[dict] | None = sbom.get("diff")
    alerts = [f for f in findings if f["severity"] == "ALERT"]
    warns = [f for f in findings if f["severity"] == "WARN"]

    verdict, label = _verdict_block(alerts, warns)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sbom_generated = sbom.get("meta", {}).get("generated_at", now)

    sections: list[list[str]] = [
        [
            f"# opencode-ai Safety Report — v{version}",
            "",
            f"**Date**: {now}  ",
            f"**SBOM generated**: {sbom_generated}  ",
            f"**Verdict**: {verdict}",
            "",
            "---",
            "",
        ],
        section_header(log_lines, domains),
        ["", "---", ""],
        section_sbom(sbom),
        ["", "---", ""],
        section_checks(sbom, log_lines, domains),
        ["", "---", ""],
        section_cves(sbom.get("components", [])),
        ["", "---", ""] if sbom.get("components") else [],
        section_findings(findings),
        section_baseline_diff(diff),
        ["", "---", ""],
        section_raw_urls(log_lines),
        [
            "",
            "---",
            "",
            f"*Auto-generated by opencode-investigation — report_generator.py*",
        ],
    ]

    return "\n".join(line for section in sections for line in section)


def main() -> None:
    report = generate_report(VERSION, RUN_OUTPUT_DIR)
    REPORT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUTPUT.write_text(report)
    print(f"[report] Written to {REPORT_OUTPUT}")
    print()
    print(report)


if __name__ == "__main__":
    main()
