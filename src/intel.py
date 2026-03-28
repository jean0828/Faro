"""
intel.py — External Threat Intelligence & Breach Monitoring
============================================================
Placeholder module for Dark Web and credential breach intelligence,
inspired by the DarkWeb-Monitoring methodology.

Planned integrations (implement per active API subscriptions):

    1. HaveIBeenPwned (HIBP) API v3
       - /breachedaccount/{account}    → per-email breach lookup
       - /breaches?domain={domain}     → all breaches for a domain

    2. IntelligenceX API
       - Full-text search across dark web, paste sites, and breach DBs.
       - Returns document references; raw content via paid tier.

    3. LeakLookup API
       - Domain and email search across aggregated breach datasets.

    4. Shodan InternetDB (free, no key required)
       - /hosts/{ip}  → open ports, vulns, tags for a given IP.
       - Useful as a quick supplement to naabu port scanning.

    5. GreyNoise Community API
       - /v3/community/{ip} → classify IPs as benign/malicious/unknown.

Usage pattern (once implemented):
    from src.intel import run_intel
    report = await run_intel("example.com")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BreachRecord:
    source: str               # e.g. "HaveIBeenPwned", "LeakLookup"
    breach_name: str
    breach_date: Optional[str] = None
    data_classes: list[str] = field(default_factory=list)   # e.g. ["Passwords", "Emails"]
    record_count: Optional[int] = None
    description: str = ""


@dataclass
class InternetExposure:
    ip: str
    ports: list[int] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = "Shodan InternetDB"


@dataclass
class IntelResult:
    domain: str
    breach_records: list[BreachRecord] = field(default_factory=list)
    internet_exposure: list[InternetExposure] = field(default_factory=list)
    paste_mentions: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_breaches(self) -> bool:
        return len(self.breach_records) > 0

    @property
    def total_breach_records(self) -> int:
        return sum(b.record_count or 0 for b in self.breach_records)


# ---------------------------------------------------------------------------
# HIBP integration (stub — requires API key)
# ---------------------------------------------------------------------------

async def check_hibp_domain(domain: str, api_key: str) -> list[BreachRecord]:
    """
    Query the HaveIBeenPwned v3 API for all breaches associated with a domain.

    Requires a paid HIBP API key: https://haveibeenpwned.com/API/Key

    Args:
        domain:  Apex domain (e.g. "example.com").
        api_key: HIBP v3 API key from environment / settings.

    Returns:
        List of BreachRecord objects, one per breach.
    """
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "Faro-ASM-Tool/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return []   # No breaches found — normal response
        raise

    records: list[BreachRecord] = []
    for breach in resp.json():
        records.append(BreachRecord(
            source="HaveIBeenPwned",
            breach_name=breach.get("Name", ""),
            breach_date=breach.get("BreachDate"),
            data_classes=breach.get("DataClasses", []),
            record_count=breach.get("PwnCount"),
            description=breach.get("Description", ""),
        ))
    return records


# ---------------------------------------------------------------------------
# Shodan InternetDB integration (free, no key required)
# ---------------------------------------------------------------------------

async def check_internetdb(ip: str) -> Optional[InternetExposure]:
    """
    Query Shodan's free InternetDB API for open ports and known CVEs on an IP.

    No API key required. Rate-limited by Shodan.

    Args:
        ip: IPv4 address string.

    Returns:
        InternetExposure dataclass or None if IP not indexed.
    """
    url = f"https://internetdb.shodan.io/{ip}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"User-Agent": "Faro-ASM-Tool/1.0"})
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[intel] InternetDB query failed for %s: %s", ip, exc)
        return None

    return InternetExposure(
        ip=ip,
        ports=data.get("ports", []),
        cves=data.get("vulns", []),
        tags=data.get("tags", []),
    )


# ---------------------------------------------------------------------------
# Orchestrated intel pipeline
# ---------------------------------------------------------------------------

async def run_intel(
    domain: str,
    ips: Optional[list[str]] = None,
    hibp_api_key: Optional[str] = None,
) -> IntelResult:
    """
    Run the full threat intelligence pipeline for a domain.

    Args:
        domain:       Apex domain to investigate.
        ips:          Optional list of resolved IPs for InternetDB lookup.
        hibp_api_key: HIBP v3 API key (skipped if not provided).

    Returns:
        IntelResult aggregating all threat intelligence findings.
    """
    import asyncio

    result = IntelResult(domain=domain)

    # --- Breach data via HIBP ---
    if hibp_api_key:
        logger.info("[intel] Querying HIBP for domain %s", domain)
        try:
            result.breach_records = await check_hibp_domain(domain, hibp_api_key)
            logger.info("[intel] HIBP returned %d breach records", len(result.breach_records))
        except Exception as exc:
            logger.error("[intel] HIBP query failed: %s", exc)
            result.errors.append(f"HIBP: {exc}")
    else:
        logger.info("[intel] HIBP API key not configured — skipping breach lookup")
        result.errors.append("HIBP API key not set (set HIBP_API_KEY env var to enable)")

    # --- Internet exposure via Shodan InternetDB ---
    if ips:
        logger.info("[intel] Querying Shodan InternetDB for %d IPs", len(ips))
        exposure_tasks = [check_internetdb(ip) for ip in ips]
        exposures = await asyncio.gather(*exposure_tasks, return_exceptions=True)
        for exp in exposures:
            if isinstance(exp, InternetExposure):
                result.internet_exposure.append(exp)
            elif isinstance(exp, Exception):
                result.errors.append(f"InternetDB error: {exp}")

    # TODO: Add IntelligenceX, LeakLookup, and GreyNoise integrations
    # when corresponding API keys are configured.

    return result
