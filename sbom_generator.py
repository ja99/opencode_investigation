#!/usr/bin/env python3
"""SBOM generator for opencode-ai runtime dependencies.

Parses captured network traffic (urls.log) to build a Software Bill of
Materials for packages fetched at runtime. Checks for:
- Supply chain attack indicators (postinstall scripts, the Cline attack vector)
- Known CVEs via the OSV API (https://osv.dev) — no API key required
- Integrity hash changes vs a saved baseline

Usage:
    uv run python sbom_generator.py
    URL_LOG_FILE=./output/urls.log uv run python sbom_generator.py
"""

import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Literal, NotRequired, TypedDict
from urllib.parse import unquote

import httpx

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME = "opencode-investigation-sbom"
TOOL_VERSION = "1.1.0"

URL_LOG_FILE = os.environ.get("URL_LOG_FILE", "./output/urls.log")
SBOM_OUTPUT = os.environ.get("SBOM_OUTPUT", "./output/sbom.json")
SBOM_BASELINE = os.environ.get("SBOM_BASELINE", "./output/sbom_baseline.json")

TRUSTED_BINARY_HOSTS = {"github.com", "release-assets.githubusercontent.com"}

# OSV ecosystem for known binary tools (used for CVE lookups)
BINARY_ECOSYSTEMS: dict[str, str] = {
    "ripgrep": "crates.io",
}

# Script content patterns that indicate supply chain attack attempts
SUSPICIOUS_SCRIPT_PATTERNS: list[str] = [
    r"npm\s+install\s+-g",
    r"curl\s+[^\s]*\s*\|",
    r"wget\s+[^\s]*\s*\|",
    r"\beval\b",
    r"base64\s+-d",
    r"bash\s+-c",
    r"sh\s+-c",
]

# CVE severity → finding severity mapping
CVE_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "ALERT",
    "HIGH": "ALERT",
    "MODERATE": "WARN",
    "MEDIUM": "WARN",
    "LOW": "INFO",
}

# ── TypedDicts ────────────────────────────────────────────────────────────────


class NpmScripts(TypedDict):
    preinstall: NotRequired[str]
    install: NotRequired[str]
    postinstall: NotRequired[str]


class CveInfo(TypedDict):
    id: str              # Preferred ID: CVE-xxxx or GHSA-xxxx or OSV ID
    aliases: list[str]   # All other IDs for this vulnerability
    summary: str
    severity: str | None  # "CRITICAL", "HIGH", "MODERATE", "LOW", or None
    details_url: str     # https://osv.dev/vulnerability/<osv_id>


class SbomMeta(TypedDict):
    tool: str
    tool_version: str
    generated_at: str
    urls_log: str


class NpmComponent(TypedDict):
    type: Literal["npm"]
    name: str
    version: str
    source_url: str
    registry_url: str
    integrity: str | None
    scripts: NpmScripts
    dependencies: dict[str, str]
    registry_fetch_ok: bool
    cves: list[CveInfo]


class BinaryComponent(TypedDict):
    type: Literal["binary"]
    name: str
    version: str | None
    source_url: str
    filename: str
    cves: list[CveInfo]


Component = NpmComponent | BinaryComponent

FindingSeverity = Literal["ALERT", "WARN", "INFO"]


class Finding(TypedDict):
    severity: FindingSeverity
    component: str
    check: str
    detail: str


class DiffEntry(TypedDict):
    change: Literal[
        "new_package",
        "version_change",
        "script_change",
        "integrity_change",
        "removed_package",
    ]
    component: str
    before: str | None
    after: str | None


class Sbom(TypedDict):
    meta: SbomMeta
    components: list[Component]
    findings: list[Finding]
    diff: list[DiffEntry] | None


# ── URL Log Parsing ───────────────────────────────────────────────────────────


def parse_urls_log(log_path: str) -> list[str]:
    """Return all GET request URLs from the log."""
    urls: list[str] = []
    if not os.path.exists(log_path):
        return urls
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("GET "):
                urls.append(line[4:].strip())
    return urls


def extract_npm_tarballs(urls: list[str]) -> list[tuple[str, str, str]]:
    """
    Returns list of (name, version, url) for npm .tgz downloads.
    Handles both scoped (@scope/pkg) and unscoped packages.
    """
    results: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    scoped_re = re.compile(
        r"registry\.npmjs\.org/(@[^/]+/[^/]+)/-/[^/]+-(\d+\.\d+\.\d+[^/]*)\.tgz"
    )
    unscoped_re = re.compile(
        r"registry\.npmjs\.org/([^/@][^/]*)/-/[^/]+-(\d+\.\d+\.\d+[^/]*)\.tgz"
    )

    for url in urls:
        m = scoped_re.search(url) or unscoped_re.search(url)
        if m:
            name, version = m.group(1), m.group(2)
            key = (name, version)
            if key not in seen:
                seen.add(key)
                results.append((name, version, url))

    return results


def extract_npm_metadata_fetches(urls: list[str]) -> set[str]:
    """
    Returns package names from metadata-only fetches (no /-/ tarball segment).
    Decodes %2f -> / for scoped packages.
    """
    names: set[str] = set()
    meta_re = re.compile(r"registry\.npmjs\.org/([^?#]+)$")

    for url in urls:
        m = meta_re.search(url)
        if m and "/-/" not in url and ".tgz" not in url:
            names.add(unquote(m.group(1).rstrip("/")))

    return names


def extract_binary_downloads(urls: list[str]) -> list[BinaryComponent]:
    """
    Detects GitHub release binary downloads.
    Deduplicates the release-assets.githubusercontent.com CDN redirect by filename.
    """
    components: list[BinaryComponent] = []
    seen_filenames: set[str] = set()
    github_re = re.compile(
        r"github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/([^?#]+)"
    )

    for url in urls:
        m = github_re.search(url)
        if m:
            _owner, repo, version, filename = m.group(1), m.group(2), m.group(3), m.group(4)
            if filename not in seen_filenames:
                seen_filenames.add(filename)
                components.append(
                    BinaryComponent(
                        type="binary",
                        name=repo,
                        version=version,
                        source_url=url,
                        filename=filename,
                        cves=[],
                    )
                )

    return components


def merge_npm_packages(
    tarballs: list[tuple[str, str, str]],
    metadata_fetches: set[str],
) -> list[tuple[str, str | None, str]]:
    result: list[tuple[str, str | None, str]] = [
        (name, version, url) for name, version, url in tarballs
    ]
    tarball_names = {name for name, _, _ in tarballs}
    for name in metadata_fetches:
        if name not in tarball_names:
            result.append((name, None, f"https://registry.npmjs.org/{name}"))
    return result


# ── npm Registry Enrichment ───────────────────────────────────────────────────


async def fetch_npm_metadata(
    client: httpx.AsyncClient,
    name: str,
    version: str | None,
) -> dict | None:
    base = "https://registry.npmjs.org"
    try:
        url = f"{base}/{name}/{version}" if version else f"{base}/{name}"
        resp = await client.get(url)
        resp.raise_for_status()
        data: dict = resp.json()
        if not version:
            latest = data.get("dist-tags", {}).get("latest")
            if latest and "versions" in data:
                data = data["versions"].get(latest, data)
        return data
    except Exception:
        return None


async def enrich_all_packages(
    packages: list[tuple[str, str | None, str]],
    concurrency: int = 5,
) -> list[NpmComponent]:
    semaphore = asyncio.Semaphore(concurrency)

    async def fetch_one(
        client: httpx.AsyncClient,
        name: str,
        version: str | None,
        source_url: str,
    ) -> NpmComponent:
        async with semaphore:
            data = await fetch_npm_metadata(client, name, version)
        return build_npm_component(name, version, source_url, data)

    async with httpx.AsyncClient(timeout=10.0, proxy=None) as client:
        tasks = [fetch_one(client, name, version, url) for name, version, url in packages]
        return list(await asyncio.gather(*tasks))


def build_npm_component(
    name: str,
    version: str | None,
    source_url: str,
    registry_data: dict | None,
) -> NpmComponent:
    if registry_data is None:
        return NpmComponent(
            type="npm",
            name=name,
            version=version or "unknown",
            source_url=source_url,
            registry_url="",
            integrity=None,
            scripts=NpmScripts(),
            dependencies={},
            registry_fetch_ok=False,
            cves=[],
        )

    dist = registry_data.get("dist", {})
    raw_scripts = registry_data.get("scripts", {})
    scripts = NpmScripts()
    for key in ("preinstall", "install", "postinstall"):
        if key in raw_scripts:
            scripts[key] = raw_scripts[key]  # type: ignore[literal-required]

    return NpmComponent(
        type="npm",
        name=name,
        version=registry_data.get("version") or version or "unknown",
        source_url=source_url,
        registry_url=dist.get("tarball", ""),
        integrity=dist.get("integrity"),
        scripts=scripts,
        dependencies=registry_data.get("dependencies", {}),
        registry_fetch_ok=True,
        cves=[],
    )


# ── CVE Lookup (OSV API) ──────────────────────────────────────────────────────


def _parse_osv_severity(vuln: dict) -> str | None:
    """Extract a severity label from an OSV vulnerability record.

    Prefers the GitHub Advisory Database's human-readable label
    (database_specific.severity) over CVSS vector strings.
    """
    sev = vuln.get("database_specific", {}).get("severity")
    if sev:
        return sev.upper()  # "CRITICAL" | "HIGH" | "MODERATE" | "LOW"
    # Fall back to CVSS type; without parsing the vector we can only return the type
    for s in vuln.get("severity", []):
        if s.get("type") in ("CVSS_V3", "CVSS_V2"):
            return s.get("type")  # Less useful but better than nothing
    return None


def _parse_osv_vuln(vuln: dict) -> CveInfo:
    osv_id: str = vuln.get("id", "")
    aliases: list[str] = vuln.get("aliases", [])
    # Prefer CVE ID as the primary identifier
    primary = next((a for a in aliases if a.startswith("CVE-")), None)
    if not primary:
        primary = next((a for a in aliases if a.startswith("GHSA-")), osv_id)
    other_aliases = [a for a in [osv_id] + aliases if a != primary]

    return CveInfo(
        id=primary,
        aliases=other_aliases,
        summary=vuln.get("summary", ""),
        severity=_parse_osv_severity(vuln),
        details_url=f"https://osv.dev/vulnerability/{osv_id}",
    )


async def _fetch_cves_batch(
    client: httpx.AsyncClient,
    queries: list[tuple[str, str, str]],  # (name, version, ecosystem)
) -> list[list[CveInfo]]:
    """Call the OSV querybatch endpoint; returns one list per query."""
    if not queries:
        return []

    body = {
        "queries": [
            {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
            for name, version, ecosystem in queries
        ]
    }

    try:
        resp = await client.post("https://api.osv.dev/v1/querybatch", json=body)
        resp.raise_for_status()
        results: list[dict] = resp.json().get("results", [])
    except Exception:
        return [[] for _ in queries]

    return [
        [_parse_osv_vuln(v) for v in result.get("vulns", [])]
        for result in results
    ]


async def fetch_all_cves(
    client: httpx.AsyncClient,
    components: list[Component],
) -> None:
    """Fetch CVEs from OSV for all components and attach them in-place."""
    queries: list[tuple[str, str, str]] = []
    indices: list[int] = []

    for i, comp in enumerate(components):
        if comp["type"] == "npm" and comp["version"] not in ("unknown", ""):
            queries.append((comp["name"], comp["version"], "npm"))
            indices.append(i)
        elif comp["type"] == "binary":
            ecosystem = BINARY_ECOSYSTEMS.get(comp["name"])
            if ecosystem and comp.get("version"):
                queries.append((comp["name"], comp["version"], ecosystem))  # type: ignore[arg-type]
                indices.append(i)

    if not queries:
        return

    cve_lists = await _fetch_cves_batch(client, queries)
    for i, cves in zip(indices, cve_lists):
        components[i]["cves"] = cves  # type: ignore[typeddict-unknown-key]


# ── Security Analysis ─────────────────────────────────────────────────────────


def check_script_content(
    script_value: str, script_name: str, pkg: str
) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, script_value, re.IGNORECASE):
            findings.append(
                Finding(
                    severity="ALERT",
                    component=pkg,
                    check="suspicious_script_content",
                    detail=(
                        f"scripts.{script_name} matches suspicious pattern "
                        f"`{pattern}`: {script_value!r}"
                    ),
                )
            )
            break
    return findings


def analyze_components(components: list[Component]) -> list[Finding]:
    """Generate security findings from the component list."""
    findings: list[Finding] = []
    npm_count = 0
    binary_count = 0

    for comp in components:
        if comp["type"] == "npm":
            npm_count += 1
            pkg = f"{comp['name']}@{comp['version']}"
            scripts: NpmScripts = comp["scripts"]

            # Lifecycle script checks (primary Cline-attack surface)
            for script_key in ("postinstall", "preinstall", "install"):
                value = scripts.get(script_key)  # type: ignore[literal-required]
                if value:
                    findings.append(
                        Finding(
                            severity="ALERT",
                            component=pkg,
                            check=f"{script_key}_script",
                            detail=f"scripts.{script_key} = {value!r}",
                        )
                    )
                    findings.extend(check_script_content(value, script_key, pkg))

            if not comp["registry_fetch_ok"]:
                findings.append(
                    Finding(
                        severity="WARN",
                        component=pkg,
                        check="registry_fetch_failed",
                        detail="Could not fetch npm registry metadata — integrity unverifiable",
                    )
                )
            elif comp["integrity"] is None:
                findings.append(
                    Finding(
                        severity="WARN",
                        component=pkg,
                        check="missing_integrity",
                        detail="npm dist.integrity field absent despite successful registry fetch",
                    )
                )

        elif comp["type"] == "binary":
            binary_count += 1
            host = re.search(r"https?://([^/]+)", comp["source_url"])
            if host and host.group(1) not in TRUSTED_BINARY_HOSTS:
                findings.append(
                    Finding(
                        severity="WARN",
                        component=comp["name"],
                        check="unexpected_binary_cdn",
                        detail=f"Binary downloaded from untrusted host: {host.group(1)}",
                    )
                )

        # CVE findings (applies to both npm and binary)
        pkg_label = (
            f"{comp['name']}@{comp['version']}"
            if comp["type"] == "npm"
            else comp["name"]
        )
        for cve in comp.get("cves", []):
            sev = cve["severity"] or "UNKNOWN"
            finding_sev: FindingSeverity = CVE_SEVERITY_MAP.get(sev, "WARN")  # type: ignore[assignment]
            all_ids = ", ".join(filter(None, [cve["id"]] + cve["aliases"][:2]))
            findings.append(
                Finding(
                    severity=finding_sev,
                    component=pkg_label,
                    check="cve",
                    detail=f"{all_ids} [{sev}]: {cve['summary']} — {cve['details_url']}",
                )
            )

    if npm_count > 0:
        findings.append(
            Finding(
                severity="INFO",
                component="(all)",
                check="runtime_npm_install",
                detail=f"{npm_count} npm package(s) installed at runtime",
            )
        )
    if binary_count > 0:
        findings.append(
            Finding(
                severity="INFO",
                component="(all)",
                check="binary_download",
                detail=f"{binary_count} binary archive(s) downloaded at runtime",
            )
        )

    return findings


# ── Baseline Comparison ───────────────────────────────────────────────────────


def load_baseline(path: str) -> Sbom | None:
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def compare_to_baseline(current: Sbom, baseline: Sbom) -> list[DiffEntry]:
    diff: list[DiffEntry] = []

    def component_key(c: Component) -> tuple[str, str]:
        return (c["type"], c["name"])

    baseline_map = {component_key(c): c for c in baseline["components"]}
    current_map = {component_key(c): c for c in current["components"]}

    for key, comp in current_map.items():
        label = f"{comp['name']}@{comp.get('version', '?')}"
        if key not in baseline_map:
            diff.append(DiffEntry(change="new_package", component=label, before=None, after=label))
            continue

        base = baseline_map[key]

        if comp.get("version") != base.get("version"):
            diff.append(
                DiffEntry(
                    change="version_change",
                    component=comp["name"],
                    before=base.get("version"),
                    after=comp.get("version"),
                )
            )

        if comp["type"] == "npm" and base["type"] == "npm":
            if comp["scripts"] != base["scripts"]:
                diff.append(
                    DiffEntry(
                        change="script_change",
                        component=label,
                        before=json.dumps(base["scripts"]),
                        after=json.dumps(comp["scripts"]),
                    )
                )
            if (
                comp["integrity"] is not None
                and base["integrity"] is not None
                and comp["integrity"] != base["integrity"]
            ):
                diff.append(
                    DiffEntry(
                        change="integrity_change",
                        component=label,
                        before=base["integrity"],
                        after=comp["integrity"],
                    )
                )

    for key, base in baseline_map.items():
        if key not in current_map:
            label = f"{base['name']}@{base.get('version', '?')}"
            diff.append(DiffEntry(change="removed_package", component=label, before=label, after=None))

    return diff


def findings_from_diff(diff: list[DiffEntry]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in diff:
        change = entry["change"]
        comp = entry["component"]

        if change == "new_package":
            findings.append(Finding(severity="WARN", component=comp, check="baseline_new_package",
                                    detail=f"Package not present in baseline: {comp}"))
        elif change == "version_change":
            findings.append(Finding(severity="WARN", component=comp, check="baseline_version_change",
                                    detail=f"Version changed: {entry['before']} → {entry['after']}"))
        elif change == "script_change":
            after_scripts = json.loads(entry["after"] or "{}")
            if after_scripts:
                findings.append(Finding(severity="ALERT", component=comp, check="baseline_script_added",
                                        detail=f"Lifecycle scripts changed from baseline. Before: {entry['before']}  After: {entry['after']}"))
            else:
                findings.append(Finding(severity="WARN", component=comp, check="baseline_script_removed",
                                        detail=f"Lifecycle scripts removed vs baseline. Before: {entry['before']}"))
        elif change == "integrity_change":
            findings.append(Finding(severity="ALERT", component=comp, check="baseline_integrity_change",
                                    detail=f"Package integrity hash changed! Before: {entry['before']}  After: {entry['after']}"))
        elif change == "removed_package":
            findings.append(Finding(severity="INFO", component=comp, check="baseline_removed_package",
                                    detail=f"Package present in baseline but not in current run: {comp}"))

    return findings


# ── Output ────────────────────────────────────────────────────────────────────


def write_sbom(sbom: Sbom, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(sbom, f, indent=2)


def print_security_report(sbom: Sbom, baseline_created: bool) -> None:
    findings = sbom["findings"]
    alerts = [f for f in findings if f["severity"] == "ALERT"]
    warns = [f for f in findings if f["severity"] == "WARN"]
    infos = [f for f in findings if f["severity"] == "INFO"]

    npm_count = sum(1 for c in sbom["components"] if c["type"] == "npm")
    binary_count = sum(1 for c in sbom["components"] if c["type"] == "binary")
    cve_count = sum(len(c.get("cves", [])) for c in sbom["components"])

    print()
    print("=" * 56)
    print(f"  SBOM Security Report — {sbom['meta']['generated_at']}")
    print("=" * 56)
    print(f"\nComponents: {len(sbom['components'])} ({npm_count} npm, {binary_count} binary)")
    print(f"CVEs found: {cve_count}\n")

    if not findings:
        print("No findings.")
    else:
        for f in alerts + warns + infos:
            print(f"[{f['severity']:<5}] {f['component']}  [{f['check']}]")
            print(f"        {f['detail']}")

    if sbom["diff"] is not None:
        if sbom["diff"]:
            print("\n--- Baseline Diff ---")
            for entry in sbom["diff"]:
                print(f"  {entry['change'].upper().replace('_', ' ')}: {entry['component']}")
        else:
            print("\n--- Baseline Diff: no changes ---")

    print()
    print(f"  {len(alerts)} ALERT(s)  |  {len(warns)} WARN(s)  |  {len(infos)} INFO(s)  |  {cve_count} CVE(s)")
    print("=" * 56)
    print(f"\nSBOM written to: {SBOM_OUTPUT}")
    if baseline_created:
        print(f"Baseline created: {SBOM_BASELINE}")
        print("  (To update baseline: cp output/sbom.json output/sbom_baseline.json)")
    else:
        print(f"Compared against baseline: {SBOM_BASELINE}")
    print()


# ── Orchestration ─────────────────────────────────────────────────────────────


async def main() -> None:
    print(f"[SBOM] Parsing {URL_LOG_FILE} ...")
    urls = parse_urls_log(URL_LOG_FILE)

    if not urls:
        print(f"[SBOM] No GET URLs found in {URL_LOG_FILE}")

    tarballs = extract_npm_tarballs(urls)
    metadata_fetches = extract_npm_metadata_fetches(urls)
    binaries = extract_binary_downloads(urls)
    packages = merge_npm_packages(tarballs, metadata_fetches)

    print(f"[SBOM] Found {len(packages)} npm package(s), {len(binaries)} binary download(s)")
    print("[SBOM] Fetching npm registry metadata ...")
    npm_components = await enrich_all_packages(packages)

    components: list[Component] = [*npm_components, *binaries]

    print("[SBOM] Checking CVEs via OSV (https://osv.dev) ...")
    async with httpx.AsyncClient(timeout=15.0, proxy=None) as client:
        await fetch_all_cves(client, components)

    cve_total = sum(len(c.get("cves", [])) for c in components)
    print(f"[SBOM] CVE lookup complete — {cve_total} CVE(s) found across all components")

    findings = analyze_components(components)

    # Baseline comparison
    baseline = load_baseline(SBOM_BASELINE)
    diff: list[DiffEntry] | None = None
    baseline_created = False

    if baseline is not None:
        diff = compare_to_baseline(
            Sbom(meta=SbomMeta(tool="", tool_version="", generated_at="", urls_log=""),
                 components=components, findings=[], diff=None),
            baseline,
        )
        findings.extend(findings_from_diff(diff))

    sbom = Sbom(
        meta=SbomMeta(
            tool=TOOL_NAME,
            tool_version=TOOL_VERSION,
            generated_at=datetime.now(timezone.utc).isoformat(),
            urls_log=URL_LOG_FILE,
        ),
        components=components,
        findings=findings,
        diff=diff,
    )

    write_sbom(sbom, SBOM_OUTPUT)

    if baseline is None:
        write_sbom(sbom, SBOM_BASELINE)
        baseline_created = True

    print_security_report(sbom, baseline_created)

    alert_count = sum(1 for f in findings if f["severity"] == "ALERT")
    if alert_count > 0:
        sys.exit(1)


def main_sync() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
