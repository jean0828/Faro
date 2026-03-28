"""
app.py — Faro FastAPI Entry Point
==================================
Exposes a single evaluation endpoint that orchestrates the full pipeline:

    GET  /health                — liveness probe
    POST /evaluate/{domain}     — run full ASM + TPRA assessment
    GET  /evaluate/{domain}     — same as POST, for quick browser/curl testing
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from src.discovery import DiscoveryResult, run_discovery
from src.analysis import AnalysisResult, analyze_url
from src.intel import IntelResult, run_intel

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("faro.app")


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Faro starting up — environment: %s", os.getenv("FARO_ENV", "unknown"))
    yield
    logger.info("Faro shutting down")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Faro — Attack Surface Management",
    description=(
        "Automated third-party risk assessment tool combining reconnaissance, "
        "deep web scraping, and breach intelligence."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class EvaluationOptions(BaseModel):
    include_ports: bool = Field(
        default=False,
        description="Run naabu port scanning on live hosts (slower, more intrusive).",
    )
    include_intel: bool = Field(
        default=True,
        description="Query breach and internet exposure databases.",
    )
    max_hosts_to_analyze: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum number of live hosts to deep-analyze with Crawl4AI.",
    )


class SubdomainSummary(BaseModel):
    host: str
    status_code: Optional[int]
    title: Optional[str]
    tech: list[str]
    webserver: Optional[str]
    cdn: Optional[str]


class HeaderFindingSummary(BaseModel):
    header: str
    present: bool
    severity: str
    recommendation: str


class AnalysisSummary(BaseModel):
    url: str
    security_score: int
    security_grade: str
    missing_headers: list[HeaderFindingSummary]
    leaked_server_info: dict[str, str]
    sensitive_paths: list[str]
    external_scripts_count: int
    has_mixed_content: bool
    cookie_issues: list[str]


class IntelSummary(BaseModel):
    breach_count: int
    total_breached_records: int
    breach_names: list[str]
    exposed_ips: list[str]
    known_cves: list[str]
    errors: list[str]


class EvaluationReport(BaseModel):
    domain: str
    assessed_at: str
    duration_seconds: float
    live_hosts_found: int
    subdomains: list[SubdomainSummary]
    deep_analysis: list[AnalysisSummary]
    intel: Optional[IntelSummary]
    discovery_errors: list[str]
    pipeline_errors: list[str]


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _summarize_discovery(result: DiscoveryResult) -> list[SubdomainSummary]:
    return [
        SubdomainSummary(
            host=s.host,
            status_code=s.status_code,
            title=s.title,
            tech=s.tech,
            webserver=s.webserver,
            cdn=s.cdn,
        )
        for s in result.subdomains
    ]


def _summarize_analysis(result: AnalysisResult) -> AnalysisSummary:
    missing_headers = [
        HeaderFindingSummary(
            header=f.header,
            present=f.present,
            severity=f.severity,
            recommendation=f.recommendation,
        )
        for f in result.header_findings
        if not f.present
    ]

    cookie_issues: list[str] = []
    for c in result.cookie_findings:
        issues: list[str] = []
        if not c.secure:
            issues.append("missing Secure flag")
        if not c.http_only:
            issues.append("missing HttpOnly flag")
        if not c.same_site:
            issues.append("missing SameSite attribute")
        if issues:
            cookie_issues.append(f"{c.name}: {', '.join(issues)}")

    return AnalysisSummary(
        url=result.url,
        security_score=result.security_score,
        security_grade=result.security_grade,
        missing_headers=missing_headers,
        leaked_server_info=result.leak_headers,
        sensitive_paths=result.sensitive_paths,
        external_scripts_count=len(result.external_scripts),
        has_mixed_content=result.has_mixed_content,
        cookie_issues=cookie_issues,
    )


def _summarize_intel(result: IntelResult) -> IntelSummary:
    all_cves: list[str] = []
    exposed_ips: list[str] = []
    for exp in result.internet_exposure:
        exposed_ips.append(exp.ip)
        all_cves.extend(exp.cves)

    return IntelSummary(
        breach_count=len(result.breach_records),
        total_breached_records=result.total_breach_records,
        breach_names=[b.breach_name for b in result.breach_records],
        exposed_ips=exposed_ips,
        known_cves=sorted(set(all_cves)),
        errors=result.errors,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health():
    """Liveness probe — returns 200 when the service is running."""
    return {"status": "ok", "service": "faro"}


@app.api_route(
    "/evaluate/{domain}",
    methods=["GET", "POST"],
    response_model=EvaluationReport,
    tags=["Assessment"],
    summary="Run a full ASM + TPRA assessment for a domain",
)
async def evaluate_domain(
    domain: str,
    include_ports: bool = Query(default=False, description="Enable naabu port scanning"),
    include_intel: bool = Query(default=True, description="Enable breach/exposure intel"),
    max_hosts: int = Query(default=5, ge=1, le=50, description="Max hosts for deep analysis"),
):
    """
    Orchestrates the full Faro pipeline for the target domain:

    1. **Discovery** — subfinder (passive) → httpx (active probing) → optional naabu
    2. **Analysis**  — Crawl4AI / Playwright deep crawl of live hosts
    3. **Intel**     — HIBP breach lookup + Shodan InternetDB exposure data

    Returns a structured JSON report suitable for downstream risk scoring.
    """
    # Basic domain sanitization
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail=f"Invalid domain: '{domain}'")

    start = time.monotonic()
    pipeline_errors: list[str] = []

    logger.info("=== Starting evaluation for %s ===", domain)

    # --- Stage 1: Discovery ---
    try:
        discovery: DiscoveryResult = await run_discovery(domain, include_ports=include_ports)
    except Exception as exc:
        logger.exception("Discovery pipeline failed for %s", domain)
        raise HTTPException(status_code=500, detail=f"Discovery failed: {exc}")

    # --- Stage 2: Deep analysis (capped at max_hosts) ---
    urls_to_analyze: list[str] = []
    for sub in discovery.subdomains[:max_hosts]:
        if sub.status_code and 200 <= sub.status_code < 500:
            url = f"https://{sub.host}" if not sub.host.startswith("http") else sub.host
            urls_to_analyze.append(url)

    analysis_results: list[AnalysisResult] = []
    if urls_to_analyze:
        tasks = [analyze_url(url) for url in urls_to_analyze]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in raw_results:
            if isinstance(r, AnalysisResult):
                analysis_results.append(r)
            elif isinstance(r, Exception):
                pipeline_errors.append(f"Analysis error: {r}")

    # --- Stage 3: Threat intelligence ---
    intel_result: Optional[IntelResult] = None
    if include_intel:
        # Collect unique IPs from discovery for InternetDB lookups
        ips = list({
            s.ip for s in discovery.subdomains if s.ip and s.ip != s.host
        })
        hibp_key = os.getenv("HIBP_API_KEY")
        try:
            intel_result = await run_intel(domain, ips=ips, hibp_api_key=hibp_key)
        except Exception as exc:
            logger.warning("Intel pipeline failed: %s", exc)
            pipeline_errors.append(f"Intel error: {exc}")

    duration = round(time.monotonic() - start, 2)
    logger.info("=== Evaluation complete for %s in %.1fs ===", domain, duration)

    from datetime import datetime, timezone
    return EvaluationReport(
        domain=domain,
        assessed_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=duration,
        live_hosts_found=len(discovery.live_hosts),
        subdomains=_summarize_discovery(discovery),
        deep_analysis=[_summarize_analysis(r) for r in analysis_results],
        intel=_summarize_intel(intel_result) if intel_result else None,
        discovery_errors=discovery.errors,
        pipeline_errors=pipeline_errors,
    )
