"""
discovery.py — Strategic Asset Enumeration
===========================================
Implements a multi-stage subdomain and port discovery pipeline inspired by
the ViperOne / Reconbulk methodology:

    Stage 1 (Passive):  subfinder  — enumerates subdomains via certificate
                                     transparency, DNS brute-force APIs, and
                                     passive sources (VirusTotal, Shodan, etc.)
    Stage 2 (Active):   httpx      — probes live hosts, captures HTTP status,
                                     title, tech stack, and response headers.
    Stage 3 (Optional): naabu      — fast TCP port scan on live hosts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Subdomain:
    host: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech: list[str] = field(default_factory=list)
    webserver: Optional[str] = None
    cdn: Optional[str] = None
    tls: Optional[dict] = None
    raw_httpx: Optional[dict] = None


@dataclass
class DiscoveryResult:
    domain: str
    subdomains: list[Subdomain] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def live_hosts(self) -> list[str]:
        return [s.host for s in self.subdomains if s.status_code is not None]


# ---------------------------------------------------------------------------
# Tool availability checks
# ---------------------------------------------------------------------------

def _require_binary(name: str) -> str:
    """Resolve binary path or raise a clear error."""
    path = shutil.which(name)
    if path is None:
        raise EnvironmentError(
            f"Required binary '{name}' not found in PATH. "
            "Ensure the Dockerfile was built correctly."
        )
    return path


# ---------------------------------------------------------------------------
# Stage 1 — Passive subdomain enumeration (subfinder)
# ---------------------------------------------------------------------------

async def enumerate_subdomains(domain: str, timeout: int = 120) -> list[str]:
    """
    Run subfinder passively against *domain* and return a deduplicated list
    of discovered hostnames.

    subfinder flags used:
        -d      target domain
        -silent suppress banner output
        -json   machine-readable output (one JSON object per line)
        -t      concurrency threads (default 10 is fine for passive)
    """
    binary = _require_binary("subfinder")
    cmd = [binary, "-d", domain, "-silent", "-json", "-timeout", "30"]

    logger.info("[discovery] Starting passive subdomain enumeration for %s", domain)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("[discovery] subfinder timed out for %s", domain)
        return [domain]
    except Exception as exc:
        logger.error("[discovery] subfinder failed: %s", exc)
        return [domain]

    subdomains: set[str] = set()
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            # subfinder JSON schema: {"host": "sub.example.com", "source": "..."}
            host = record.get("host", "").strip()
            if host:
                subdomains.add(host)
        except json.JSONDecodeError:
            # Fallback: plain-text line is the hostname
            subdomains.add(line)

    # Always include the apex domain
    subdomains.add(domain)

    logger.info(
        "[discovery] subfinder found %d subdomains for %s", len(subdomains), domain
    )
    return sorted(subdomains)


# ---------------------------------------------------------------------------
# Stage 2 — Active HTTP probing (httpx)
# ---------------------------------------------------------------------------

async def probe_hosts(
    hosts: list[str], timeout: int = 60
) -> list[Subdomain]:
    """
    Probe a list of hostnames with httpx to identify live web assets.

    httpx flags used:
        -silent     suppress banner
        -json       JSON output per host
        -title      extract page title
        -tech-detect identify web technologies (Wappalyzer rules)
        -status-code include HTTP status
        -web-server  extract Server header value
        -cdn        detect CDN provider
        -tls-probe  basic TLS info
        -follow-redirects
        -timeout    per-request timeout (seconds)
    """
    if not hosts:
        return []

    binary = _require_binary("httpx")

    # httpx reads targets from stdin
    input_data = "\n".join(hosts).encode()

    cmd = [
        binary,
        "-silent", "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-web-server",
        "-cdn",
        "-tls-probe",
        "-follow-redirects",
        "-timeout", "10",
        "-rate-limit", "50",   # polite rate limit (req/sec)
    ]

    logger.info("[discovery] Probing %d hosts with httpx", len(hosts))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("[discovery] httpx timed out")
        return []
    except Exception as exc:
        logger.error("[discovery] httpx failed: %s", exc)
        return []

    results: list[Subdomain] = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            sub = Subdomain(
                host=record.get("input", record.get("url", "")),
                ip=record.get("host"),
                status_code=record.get("status-code") or record.get("status_code"),
                title=record.get("title"),
                tech=record.get("tech", []),
                webserver=record.get("webserver"),
                cdn=record.get("cdn"),
                tls=record.get("tls"),
                raw_httpx=record,
            )
            results.append(sub)
        except json.JSONDecodeError:
            logger.debug("[discovery] httpx non-JSON line: %s", line[:120])

    logger.info("[discovery] httpx confirmed %d live hosts", len(results))
    return results


# ---------------------------------------------------------------------------
# Stage 3 — Port scanning (naabu) — optional, targeted
# ---------------------------------------------------------------------------

async def scan_ports(
    hosts: list[str],
    ports: str = "80,443,8080,8443,8888,3000,4443",
    timeout: int = 120,
) -> dict[str, list[int]]:
    """
    Run naabu against a subset of hosts to discover open ports.

    Only call this on confirmed live hosts to avoid unnecessary noise.

    naabu flags:
        -silent     suppress banner
        -json       JSON output
        -p          comma-separated port list (or range: 1-1000)
        -rate       packets/second (keep polite)
        -timeout    milliseconds per connection
    """
    if not hosts:
        return {}

    binary = _require_binary("naabu")
    input_data = "\n".join(hosts).encode()

    cmd = [
        binary,
        "-silent", "-json",
        "-p", ports,
        "-rate", "1000",
        "-timeout", "1000",
    ]

    logger.info("[discovery] Port scanning %d hosts with naabu", len(hosts))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("[discovery] naabu timed out")
        return {}
    except Exception as exc:
        logger.error("[discovery] naabu failed: %s", exc)
        return {}

    port_map: dict[str, list[int]] = {}
    for line in stdout.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            # naabu JSON schema: {"ip": "1.2.3.4", "port": 443, "host": "sub.example.com"}
            host = record.get("host") or record.get("ip", "")
            port = record.get("port")
            if host and port:
                port_map.setdefault(host, []).append(int(port))
        except (json.JSONDecodeError, ValueError):
            pass

    return port_map


# ---------------------------------------------------------------------------
# Orchestrated pipeline
# ---------------------------------------------------------------------------

async def run_discovery(
    domain: str,
    include_ports: bool = False,
) -> DiscoveryResult:
    """
    Execute the full multi-stage discovery pipeline for a given domain.

    Args:
        domain:        The apex domain to investigate (e.g. "example.com").
        include_ports: Whether to run naabu port scanning on live hosts.

    Returns:
        DiscoveryResult with subdomains, live host details, and optional ports.
    """
    result = DiscoveryResult(domain=domain)

    # Stage 1 — Passive enumeration
    try:
        raw_hosts = await enumerate_subdomains(domain)
    except EnvironmentError as exc:
        result.errors.append(str(exc))
        raw_hosts = [domain]

    # Stage 2 — Active HTTP probing
    try:
        result.subdomains = await probe_hosts(raw_hosts)
    except EnvironmentError as exc:
        result.errors.append(str(exc))

    # Stage 3 — Port scanning (opt-in)
    if include_ports and result.live_hosts:
        try:
            result.open_ports = await scan_ports(result.live_hosts)
        except EnvironmentError as exc:
            result.errors.append(str(exc))

    return result
