# Faro — Attack Surface Management & Third-Party Risk Assessment

Faro automates the security posture evaluation of third-party integrations by combining passive reconnaissance, JavaScript-aware web crawling, and external breach intelligence into a single REST API call.

---

## Architecture

```
/evaluate/{domain}
       │
       ├─ [1] Discovery   subfinder (passive) → httpx (active probe) → naabu (ports, optional)
       ├─ [2] Analysis    Crawl4AI + Playwright → security headers, cookies, sensitive paths
       └─ [3] Intel       HIBP breach DB + Shodan InternetDB
```

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (Desktop or Engine)
- [VS Code](https://code.visualstudio.com/) with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

---

## Quick Start (Dev Container)

### 1. Clone and open in VS Code

```bash
git clone <repo-url>
cd Faro
code .
```

When VS Code prompts **"Reopen in Container"**, click it.
The first build takes ~5 minutes (downloads Go binaries and Playwright browsers).

### 2. The API starts automatically

The container runs `uvicorn src.app:app --reload` on startup.
VS Code forwards port **8000** to your localhost.

### 3. Run your first scan

```bash
# Health check
curl http://localhost:8000/health

# Full domain assessment (passive, no port scan)
curl "http://localhost:8000/evaluate/example.com"

# With port scanning enabled
curl "http://localhost:8000/evaluate/example.com?include_ports=true"

# Limit deep analysis to top 3 live hosts
curl "http://localhost:8000/evaluate/example.com?max_hosts=3"
```

Interactive API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API Reference

### `GET /evaluate/{domain}`

| Parameter       | Type    | Default | Description                                       |
|-----------------|---------|---------|---------------------------------------------------|
| `include_ports` | bool    | `false` | Run naabu TCP port scan on live hosts             |
| `include_intel` | bool    | `true`  | Query HIBP and Shodan InternetDB                  |
| `max_hosts`     | int     | `5`     | Cap on Crawl4AI deep-analysis targets (1–50)      |

**Response fields of interest:**

```json
{
  "domain": "example.com",
  "live_hosts_found": 12,
  "deep_analysis": [
    {
      "url": "https://example.com",
      "security_score": 65,
      "security_grade": "C",
      "missing_headers": [
        { "header": "content-security-policy", "severity": "HIGH", ... }
      ],
      "leaked_server_info": { "server": "nginx/1.18.0" },
      "sensitive_paths": ["https://example.com/admin"],
      "has_mixed_content": false
    }
  ],
  "intel": {
    "breach_count": 2,
    "total_breached_records": 14830221,
    "known_cves": ["CVE-2021-44228"]
  }
}
```

---

## Environment Variables

Create a `.env` file in the project root (never commit it):

```env
# Required for breach lookup via HaveIBeenPwned
HIBP_API_KEY=your_hibp_api_key_here

# Optional: subfinder API key sources
# Place provider keys in ~/.config/subfinder/provider-config.yaml
# See: https://github.com/projectdiscovery/subfinder#post-installation-instructions

LOG_LEVEL=INFO   # DEBUG | INFO | WARNING | ERROR
FARO_ENV=development
```

---

## Project Structure

```
Faro/
├── .devcontainer/
│   └── devcontainer.json     # VS Code Dev Container config
├── src/
│   ├── app.py                # FastAPI entry point + pipeline orchestration
│   ├── discovery.py          # subfinder → httpx → naabu pipeline
│   ├── analysis.py           # Crawl4AI security header & content analysis
│   └── intel.py              # Breach DB & internet exposure intel
├── Dockerfile                # Production-ready image
├── requirements.txt          # Python dependencies
└── README.md
```

---

## Extending Intel Sources

`src/intel.py` contains stubs for the following integrations — add your API key
and uncomment the relevant function call in `run_intel()`:

| Source            | What it provides                                  | Key required |
|-------------------|---------------------------------------------------|--------------|
| HaveIBeenPwned v3 | Breaches by domain, email                         | Yes (paid)   |
| IntelligenceX     | Dark web, paste sites, breach full-text search    | Yes (paid)   |
| LeakLookup        | Aggregated breach DB search                       | Yes          |
| Shodan InternetDB | Open ports + CVEs per IP (free, no key)           | No           |
| GreyNoise         | IP reputation (benign/malicious classification)   | Yes (free tier available) |

---

## Security Considerations

- Faro performs **passive enumeration only** (subfinder uses public data sources).
- `httpx` and `naabu` send real network probes — only target domains you own
  or have **written authorization** to assess.
- The Crawl4AI crawler renders JavaScript; ensure your target scope is authorized.
- Never commit `.env` files or API keys to version control.
