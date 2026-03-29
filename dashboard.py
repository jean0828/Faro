"""
Faro — Evaluación de Riesgo de Terceros Dashboard
Run with: streamlit run dashboard.py
"""

import io
import textwrap
import requests
import pandas as pd
import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Faro · TPRA Dashboard",
    page_icon="🔭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Dark-theme CSS ─────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* Global background */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    /* Metric cards */
    [data-testid="metric-container"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 20px;
    }
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: #161b22;
        border-radius: 8px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        color: #8b949e;
        border-radius: 6px;
        padding: 6px 20px;
    }
    .stTabs [aria-selected="true"] {
        background: #21262d !important;
        color: #58a6ff !important;
    }
    /* Dataframe */
    [data-testid="stDataFrame"] { border-radius: 8px; }
    /* Divider */
    hr { border-color: #30363d; }
    /* Badge helpers (used via markdown) */
    .badge-critical { background:#da3633; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; }
    .badge-high     { background:#d29922; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; }
    .badge-medium   { background:#9e6a03; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; }
    .badge-low      { background:#238636; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; }
    .badge-pass     { background:#1f6feb; color:#fff; padding:2px 8px; border-radius:4px; font-size:.8em; }
    </style>
    """,
    unsafe_allow_html=True,
)

API_BASE = "http://localhost:8000"


# ── Helpers ───────────────────────────────────────────────────────────────────

def risk_color(score: int) -> str:
    if score >= 80:
        return "#da3633"   # Critical
    if score >= 60:
        return "#d29922"   # High
    if score >= 40:
        return "#9e6a03"   # Medium
    return "#238636"       # Low


def score_to_maturity(score: int) -> tuple[str, str]:
    """Return (label, delta_color) for a 0-100 risk score."""
    if score >= 80:
        return "CRITICAL", "inverse"
    if score >= 60:
        return "HIGH", "inverse"
    if score >= 40:
        return "MEDIUM", "off"
    return "LOW", "normal"


def grade_badge(grade: str) -> str:
    colors = {
        "A+": "#238636", "A": "#238636",
        "B": "#1f6feb",
        "C": "#9e6a03",
        "D": "#d29922",
        "F": "#da3633",
    }
    bg = colors.get(grade, "#484f58")
    return (
        f'<span style="background:{bg};color:#fff;padding:2px 10px;'
        f'border-radius:4px;font-weight:700;">{grade}</span>'
    )


def severity_badge(sev: str) -> str:
    mapping = {
        "HIGH":   ("#da3633", "HIGH"),
        "MEDIUM": ("#d29922", "MED"),
        "LOW":    ("#9e6a03", "LOW"),
        "INFO":   ("#484f58", "INFO"),
        "PASS":   ("#238636", "PASS"),
    }
    bg, label = mapping.get(sev.upper(), ("#484f58", sev))
    return (
        f'<span style="background:{bg};color:#fff;padding:1px 7px;'
        f'border-radius:3px;font-size:.8em;">{label}</span>'
    )


def compute_risk_score(data: dict) -> int:
    """
    Derive a 0-100 composite risk score from EvaluationReport since the API
    does not expose one top-level field for it.

    Components:
      - Security score (lower = worse): averaged across deep_analysis hosts
      - Breach presence: +15 per breach
      - Exposed IPs / CVEs: +5 each (capped)
    """
    analyses = data.get("deep_analysis", [])
    if analyses:
        avg_security = sum(a.get("security_score", 50) for a in analyses) / len(analyses)
        base = 100 - avg_security          # invert so high = more risky
    else:
        base = 50.0

    intel = data.get("intel") or {}
    breach_penalty = min(intel.get("breach_count", 0) * 15, 30)
    cve_penalty    = min(len(intel.get("known_cves", [])) * 5, 20)
    ip_penalty     = min(len(intel.get("exposed_ips", [])) * 5, 15)

    return min(int(base + breach_penalty + cve_penalty + ip_penalty), 100)


def fetch_report(domain: str, include_intel: bool, max_hosts: int) -> dict | None:
    url = f"{API_BASE}/evaluate/{domain}"
    params = {"include_intel": include_intel, "max_hosts_to_analyze": max_hosts}
    try:
        resp = requests.get(url, params=params, timeout=300)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error(
            "**Connection refused.** The Faro API is not reachable at "
            f"`{API_BASE}`. Make sure the backend container is running."
        )
    except requests.exceptions.Timeout:
        st.error("**Request timed out.** The scan is taking too long — try reducing *Max hosts*.")
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code
        if code == 422:
            st.error(f"**Invalid domain** `{domain}`. Please enter a valid hostname (e.g. `example.com`).")
        else:
            st.error(f"**API error {code}:** {exc.response.text[:300]}")
    except Exception as exc:
        st.error(f"**Unexpected error:** {exc}")
    return None


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🔭 Faro")
    st.markdown("**Evaluación de Riesgo de Terceros**")
    st.divider()

    domain_input = st.text_input(
        "Dominio a Evaluar",
        placeholder="example.com",
        help="Enter the root domain to scan (no scheme/path).",
    )

    with st.expander("Configuración Avanzada"):
        include_intel = st.toggle("Include Threat Intel", value=True)
        max_hosts = st.slider("Max Hosts to Analyze", min_value=1, max_value=20, value=5)

    run_btn = st.button("🚀 Iniciar Escaneo", use_container_width=True, type="primary")
    st.divider()

    # PDF placeholder
    st.download_button(
        label="📄 Download PDF Report",
        data=io.BytesIO(b"PDF generation coming soon."),
        file_name="faro_report.pdf",
        mime="application/pdf",
        use_container_width=True,
        disabled=True,
        help="PDF export will be available in a future release.",
    )

    st.caption("Tecnología base: ProjectDiscovery · Crawl4AI · HaveIBeenPwned")


# ── Main area ─────────────────────────────────────────────────────────────────

st.markdown("# Faro — Análisis de Postura de Seguridad")
st.markdown("Ingrese un dominio en el panel lateral y haga clic en'Iniciar Escaneo' para comenzar.")

if run_btn:
    if not domain_input.strip():
        st.warning("Please enter a target domain before scanning.")
        st.stop()

    domain = domain_input.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")

    with st.spinner(f"Scanning **{domain}** — this may take a few minutes…"):
        report = fetch_report(domain, include_intel, max_hosts)

    if report is None:
        st.stop()

    risk_score = compute_risk_score(report)
    maturity, delta_color = score_to_maturity(risk_score)
    analyses   = report.get("deep_analysis", [])
    subdomains = report.get("subdomains", [])
    intel      = report.get("intel") or {}

    # ── Header metrics ─────────────────────────────────────────────────────
    st.divider()
    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Risk Score", f"{risk_score} / 100", delta=maturity, delta_color=delta_color)
    col2.metric("Maturity Level", maturity)
    col3.metric("Live Hosts", report.get("live_hosts_found", len(subdomains)))
    col4.metric("Breaches Found", intel.get("breach_count", "N/A"))
    col5.metric(
        "Avg Security Score",
        f"{int(sum(a.get('security_score',0) for a in analyses)/len(analyses))}/100"
        if analyses else "N/A",
    )

    # Coloured risk banner
    banner_color = risk_color(risk_score)
    st.markdown(
        f'<div style="background:{banner_color}20;border-left:4px solid {banner_color};'
        f'padding:10px 16px;border-radius:4px;margin:8px 0;">'
        f'<b style="color:{banner_color};">⚠ {maturity} RISK</b> — '
        f'Domain <code>{domain}</code> assessed at <b>{report.get("assessed_at","")}</b> '
        f'in <b>{report.get("duration_seconds",0):.1f}s</b>'
        f"</div>",
        unsafe_allow_html=True,
    )

    st.divider()

    # ── Tabs ───────────────────────────────────────────────────────────────
    tab_surface, tab_posture, tab_intel = st.tabs(
        ["🌐  Attack Surface", "🛡  Security Posture", "🔍  Threat Intelligence"]
    )

    # ── Tab 1: Attack Surface ──────────────────────────────────────────────
    with tab_surface:
        st.subheader(f"Discovered Hosts ({len(subdomains)})")

        if not subdomains:
            st.info("No subdomains were discovered for this target.")
        else:
            rows = []
            for s in subdomains:
                rows.append({
                    "Host":       s.get("host", ""),
                    "Status":     s.get("status_code") or "—",
                    "Title":      s.get("title") or "—",
                    "Tech Stack": ", ".join(s.get("tech", [])) or "—",
                    "Web Server": s.get("webserver") or "—",
                    "CDN":        s.get("cdn") or "—",
                })
            df = pd.DataFrame(rows)

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Host":   st.column_config.TextColumn("Host", width="medium"),
                    "Status": st.column_config.NumberColumn("HTTP", width="small"),
                },
            )

        errs = report.get("discovery_errors", [])
        if errs:
            with st.expander("⚠ Discovery Errors"):
                for e in errs:
                    st.caption(f"• {e}")

    # ── Tab 2: Security Posture ────────────────────────────────────────────
    with tab_posture:
        if not analyses:
            st.info("No deep analysis was performed (no live hosts or analysis skipped).")
        else:
            for analysis in analyses:
                url   = analysis.get("url", "")
                score = analysis.get("security_score", 0)
                grade = analysis.get("security_grade", "?")

                with st.expander(
                    f"{url}  —  Score: {score}/100  Grade: {grade}",
                    expanded=(analyses.index(analysis) == 0),
                ):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Security Score", f"{score}/100")
                    c2.markdown(f"**Grade** &nbsp; {grade_badge(grade)}", unsafe_allow_html=True)
                    c3.metric("External Scripts", analysis.get("external_scripts_count", 0))

                    # Security headers table
                    headers = analysis.get("missing_headers", [])
                    if headers:
                        st.markdown("**Security Headers**")
                        hrows = []
                        for h in headers:
                            present  = h.get("present", False)
                            severity = h.get("severity", "")
                            # Skip PASS entries to keep table short; show them collapsed
                            hrows.append({
                                "_present": present,
                                "Header":         h.get("header", ""),
                                "Status":         "✅ Present" if present else "❌ Missing",
                                "Severity":       severity,
                                "Recommendation": textwrap.shorten(
                                    h.get("recommendation", ""), width=80, placeholder="…"
                                ),
                            })

                        hdf = pd.DataFrame(hrows)

                        def colour_status(val):
                            if "Present" in str(val):
                                return "background-color:#0d2818;color:#3fb950"
                            return "background-color:#2d1117;color:#f85149"

                        def colour_severity(val):
                            palette = {
                                "HIGH":   "background-color:#2d1117;color:#f85149",
                                "MEDIUM": "background-color:#271e00;color:#e3b341",
                                "LOW":    "background-color:#1b2a1b;color:#3fb950",
                                "INFO":   "background-color:#1c2128;color:#8b949e",
                                "PASS":   "background-color:#0d2818;color:#3fb950",
                            }
                            return palette.get(str(val).upper(), "")

                        styled = (
                            hdf.drop(columns=["_present"])
                            .style
                            .applymap(colour_status, subset=["Status"])
                            .applymap(colour_severity, subset=["Severity"])
                        )
                        st.dataframe(styled, use_container_width=True, hide_index=True)

                    # Leaked server info
                    leaked = analysis.get("leaked_server_info", {})
                    if leaked:
                        st.markdown("**Information Leakage Headers**")
                        st.json(leaked)

                    # Sensitive paths
                    paths = analysis.get("sensitive_paths", [])
                    if paths:
                        st.markdown("**Exposed Sensitive Paths**")
                        for p in paths:
                            st.code(p)

                    # Cookie issues
                    cookie_issues = analysis.get("cookie_issues", [])
                    if cookie_issues:
                        st.markdown("**Cookie Issues**")
                        for ci in cookie_issues:
                            st.warning(ci)

                    flags = []
                    if analysis.get("has_mixed_content"):
                        flags.append("⚠ Mixed Content detected (HTTP resources on HTTPS page)")
                    for f in flags:
                        st.error(f)

        perrs = report.get("pipeline_errors", [])
        if perrs:
            with st.expander("⚠ Pipeline Errors"):
                for e in perrs:
                    st.caption(f"• {e}")

    # ── Tab 3: Threat Intelligence ─────────────────────────────────────────
    with tab_intel:
        if not include_intel:
            st.info("Threat intel was disabled for this scan.")
        elif not intel:
            st.info("No threat intelligence data was returned.")
        else:
            i1, i2, i3 = st.columns(3)
            i1.metric("Data Breaches", intel.get("breach_count", 0))
            i2.metric(
                "Breached Records",
                f"{intel.get('total_breached_records', 0):,}",
            )
            i3.metric("Exposed IPs", len(intel.get("exposed_ips", [])))

            st.divider()

            # Breaches list
            breaches = intel.get("breach_names", [])
            if breaches:
                st.markdown("### Known Breach Events")
                bcols = st.columns(min(len(breaches), 4))
                for idx, b in enumerate(breaches):
                    bcols[idx % 4].error(f"🔴 {b}")

            # Exposed IPs
            ips = intel.get("exposed_ips", [])
            if ips:
                st.markdown("### Exposed IP Addresses")
                st.dataframe(
                    pd.DataFrame({"IP Address": ips}),
                    use_container_width=True,
                    hide_index=True,
                )

            # CVEs
            cves = intel.get("known_cves", [])
            if cves:
                st.markdown("### Known CVEs")
                cve_df = pd.DataFrame({"CVE ID": cves})
                st.dataframe(cve_df, use_container_width=True, hide_index=True)

            # Intel errors
            ierrs = intel.get("errors", [])
            if ierrs:
                with st.expander("⚠ Intel Errors"):
                    for e in ierrs:
                        st.caption(f"• {e}")
