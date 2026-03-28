"""
analysis.py — Deep Content Extraction & Security Header Analysis
================================================================
Uses Crawl4AI with Playwright (Chromium) to perform a JavaScript-aware
crawl of a target URL, then extracts security-relevant signals:

    - HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
    - Technology fingerprints from meta tags and scripts
    - Sensitive endpoint patterns (login, admin, API paths)
    - Cookie security attributes
    - Mixed-content indicators
    - Raw LLM-ready Markdown of the page for downstream analysis

Design notes:
    - All analysis is read-only; no form submissions or authenticated crawls.
    - Crawl4AI handles JS rendering, so single-page apps are handled correctly.
    - The SecurityHeaderAnalyzer grades headers per OWASP recommendations.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security header definitions (OWASP hardening guide)
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "severity": "HIGH",
    },
    "content-security-policy": {
        "description": "Content Security Policy (CSP)",
        "recommendation": "default-src 'self'; object-src 'none'",
        "severity": "HIGH",
    },
    "x-content-type-options": {
        "description": "MIME-Type Sniffing Prevention",
        "recommendation": "nosniff",
        "severity": "MEDIUM",
    },
    "x-frame-options": {
        "description": "Clickjacking Protection",
        "recommendation": "DENY or SAMEORIGIN",
        "severity": "MEDIUM",
    },
    "referrer-policy": {
        "description": "Referrer Information Leakage Control",
        "recommendation": "strict-origin-when-cross-origin",
        "severity": "LOW",
    },
    "permissions-policy": {
        "description": "Browser Feature Permissions",
        "recommendation": "camera=(), microphone=(), geolocation=()",
        "severity": "LOW",
    },
    "cross-origin-opener-policy": {
        "description": "Cross-Origin Opener Policy (COOP)",
        "recommendation": "same-origin",
        "severity": "MEDIUM",
    },
    "cross-origin-resource-policy": {
        "description": "Cross-Origin Resource Policy (CORP)",
        "recommendation": "same-origin",
        "severity": "MEDIUM",
    },
}

LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
]

# Paths that, if present, warrant further investigation
SENSITIVE_PATH_PATTERNS = [
    r"/admin", r"/administrator", r"/wp-admin", r"/wp-login",
    r"/login", r"/signin", r"/auth",
    r"/api/", r"/v1/", r"/v2/", r"/graphql", r"/swagger", r"/openapi",
    r"\.git", r"\.env", r"\.htaccess",
    r"/phpmyadmin", r"/actuator", r"/__debug__",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: Optional[str] = None
    severity: str = "INFO"
    description: str = ""
    recommendation: str = ""


@dataclass
class CookieFinding:
    name: str
    secure: bool
    http_only: bool
    same_site: Optional[str]
    domain: Optional[str] = None


@dataclass
class AnalysisResult:
    url: str
    final_url: str = ""
    status_code: Optional[int] = None

    # Security header grades
    header_findings: list[HeaderFinding] = field(default_factory=list)
    leak_headers: dict[str, str] = field(default_factory=dict)
    security_score: int = 0          # 0-100
    security_grade: str = "F"

    # Content signals
    technologies: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    cookie_findings: list[CookieFinding] = field(default_factory=list)
    external_scripts: list[str] = field(default_factory=list)
    has_mixed_content: bool = False

    # LLM-ready output
    markdown_content: str = ""

    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Header analysis helpers
# ---------------------------------------------------------------------------

class SecurityHeaderAnalyzer:
    """Grades security headers against OWASP recommendations."""

    def analyze(self, headers: dict[str, str]) -> tuple[list[HeaderFinding], dict[str, str], int, str]:
        """
        Returns (findings, leaked_headers, score_0_to_100, grade_letter).
        """
        normalized = {k.lower(): v for k, v in headers.items()}
        findings: list[HeaderFinding] = []
        missing_penalty = 0

        for header, meta in REQUIRED_HEADERS.items():
            value = normalized.get(header)
            present = value is not None
            severity = meta["severity"] if not present else "PASS"

            if not present:
                weight = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(meta["severity"], 5)
                missing_penalty += weight

            findings.append(HeaderFinding(
                header=header,
                present=present,
                value=value,
                severity=severity,
                description=meta["description"],
                recommendation="" if present else meta["recommendation"],
            ))

        # Check for information-leaking headers
        leaked: dict[str, str] = {}
        for h in LEAK_HEADERS:
            val = normalized.get(h)
            if val:
                leaked[h] = val

        # Extra penalty for tech disclosure
        missing_penalty += len(leaked) * 3

        score = max(0, 100 - missing_penalty)
        grade = self._score_to_grade(score)
        return findings, leaked, score, grade

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score >= 90:
            return "A+"
        if score >= 80:
            return "A"
        if score >= 70:
            return "B"
        if score >= 60:
            return "C"
        if score >= 50:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# Cookie analysis
# ---------------------------------------------------------------------------

def _analyze_cookies(cookies: list[dict]) -> list[CookieFinding]:
    findings: list[CookieFinding] = []
    for c in cookies:
        findings.append(CookieFinding(
            name=c.get("name", ""),
            secure=c.get("secure", False),
            http_only=c.get("httpOnly", False),
            same_site=c.get("sameSite"),
            domain=c.get("domain"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Link / path analysis
# ---------------------------------------------------------------------------

def _extract_sensitive_paths(links: list[str], base_domain: str) -> list[str]:
    found: list[str] = []
    pattern = re.compile("|".join(SENSITIVE_PATH_PATTERNS), re.IGNORECASE)
    for link in links:
        parsed = urlparse(link)
        # Only flag same-domain paths
        if base_domain in parsed.netloc or not parsed.netloc:
            path = parsed.path
            if pattern.search(path):
                found.append(link)
    return sorted(set(found))


def _extract_external_scripts(html: str, base_domain: str) -> list[str]:
    """Pull src= attributes from <script> tags pointing to third-party hosts."""
    script_re = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    externals: list[str] = []
    for match in script_re.finditer(html):
        src = match.group(1)
        parsed = urlparse(src)
        if parsed.netloc and base_domain not in parsed.netloc:
            externals.append(src)
    return sorted(set(externals))


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------

async def analyze_url(url: str, timeout: int = 30) -> AnalysisResult:
    """
    Perform a full security analysis of the given URL using Crawl4AI.

    The crawler renders JavaScript via Playwright/Chromium, so dynamically
    loaded content is captured. Analysis is completely passive (read-only).

    Args:
        url:     Target URL (e.g. "https://example.com").
        timeout: Per-request timeout in seconds.

    Returns:
        AnalysisResult with header grades, tech signals, and Markdown content.
    """
    result = AnalysisResult(url=url)
    base_domain = urlparse(url).netloc

    browser_config = BrowserConfig(
        headless=True,
        verbose=False,
        # Use the Playwright Chromium installed in the Docker image
        browser_type="chromium",
        extra_args=["--no-sandbox", "--disable-dev-shm-usage"],
    )

    run_config = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,           # Always fetch fresh
        page_timeout=timeout * 1000,           # milliseconds
        wait_until="networkidle",
        magic=True,                            # Auto-handle overlays/cookies banners
        exclude_external_links=False,          # We want all links for path analysis
        process_iframes=False,
        remove_overlay_elements=True,
    )

    logger.info("[analysis] Crawling %s", url)

    try:
        async with AsyncWebCrawler(config=browser_config) as crawler:
            crawl_result = await crawler.arun(url=url, config=run_config)
    except Exception as exc:
        logger.error("[analysis] Crawl4AI failed for %s: %s", url, exc)
        result.errors.append(f"Crawl failed: {exc}")
        return result

    if not crawl_result.success:
        result.errors.append(f"Crawl unsuccessful: {crawl_result.error_message}")
        return result

    # --- Populate basic fields ---
    result.final_url = crawl_result.url or url
    result.status_code = crawl_result.status_code
    result.markdown_content = crawl_result.markdown or ""

    # --- Security headers ---
    headers: dict[str, str] = dict(crawl_result.response_headers or {})
    analyzer = SecurityHeaderAnalyzer()
    result.header_findings, result.leak_headers, result.security_score, result.security_grade = (
        analyzer.analyze(headers)
    )

    # --- Technology fingerprinting (from httpx + Crawl4AI metadata) ---
    metadata = crawl_result.metadata or {}
    result.technologies = metadata.get("technologies", [])

    # --- Cookies ---
    # crawl4ai >=0.8.x removed the top-level .cookies attribute; guard with getattr
    raw_cookies = getattr(crawl_result, "cookies", None)
    if raw_cookies:
        result.cookie_findings = _analyze_cookies(raw_cookies)

    # --- Links & sensitive paths ---
    all_links = [lk.get("href", "") for lk in (crawl_result.links or {}).get("internal", [])]
    all_links += [lk.get("href", "") for lk in (crawl_result.links or {}).get("external", [])]
    result.sensitive_paths = _extract_sensitive_paths(all_links, base_domain)

    # --- External scripts (supply chain risk indicator) ---
    if crawl_result.html:
        result.external_scripts = _extract_external_scripts(crawl_result.html, base_domain)
        result.has_mixed_content = bool(
            re.search(r'src=["\']http://', crawl_result.html, re.IGNORECASE)
        )

    logger.info(
        "[analysis] Done for %s — score=%d grade=%s",
        url, result.security_score, result.security_grade,
    )
    return result


# ---------------------------------------------------------------------------
# Convenience: analyze multiple hosts
# ---------------------------------------------------------------------------

async def analyze_hosts(urls: list[str]) -> list[AnalysisResult]:
    """Run analyze_url concurrently across a list of URLs."""
    import asyncio
    tasks = [analyze_url(url) for url in urls]
    return await asyncio.gather(*tasks, return_exceptions=False)
