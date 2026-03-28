# =============================================================================
# Faro - Attack Surface Management & Third-Party Risk Assessment Tool
# Base: Python 3.11 on Debian Bookworm Slim
# =============================================================================

FROM python:3.11-slim-bookworm AS base

# --------------------------------------------------------------------------- #
# System dependencies
# --------------------------------------------------------------------------- #
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl wget git unzip ca-certificates gnupg \
    # Build tools (needed by some Python packages)
    gcc g++ make \
    # Networking tools for manual validation
    dnsutils iputils-ping \
    # Playwright system dependencies
    libglib2.0-0 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    libx11-6 libx11-xcb1 libxcb1 libxext6 libxtst6 libxss1 libxi6 \
    fonts-liberation fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------------- #
# Go runtime (needed to run ProjectDiscovery binaries from source if needed)
# Using pre-built binaries instead for speed — Go runtime kept for flexibility
# --------------------------------------------------------------------------- #
ENV GO_VERSION=1.22.3
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xzf -

# --------------------------------------------------------------------------- #
# Python dependencies
# --------------------------------------------------------------------------- #
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install Playwright browser (Chromium only — smallest footprint)
RUN playwright install chromium \
    && playwright install-deps chromium

# --------------------------------------------------------------------------- #
# ProjectDiscovery security binaries
# Installed AFTER pip to avoid the Python httpx CLI overwriting pd-httpx.
# --------------------------------------------------------------------------- #
ENV PD_VERSION_SUBFINDER=v2.6.6
ENV PD_VERSION_HTTPX=v1.6.8
ENV PD_VERSION_NAABU=v2.3.1

RUN set -ex; \
    # subfinder — passive subdomain enumeration
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/${PD_VERSION_SUBFINDER}/subfinder_${PD_VERSION_SUBFINDER#v}_linux_amd64.zip" \
        -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /usr/local/bin subfinder \
    && chmod +x /usr/local/bin/subfinder \
    # httpx — HTTP probing and fingerprinting (overwrites Python httpx CLI intentionally)
    && curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/${PD_VERSION_HTTPX}/httpx_${PD_VERSION_HTTPX#v}_linux_amd64.zip" \
        -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /usr/local/bin httpx \
    && chmod +x /usr/local/bin/httpx \
    # naabu — fast port scanner
    && curl -fsSL "https://github.com/projectdiscovery/naabu/releases/download/${PD_VERSION_NAABU}/naabu_${PD_VERSION_NAABU#v}_linux_amd64.zip" \
        -o /tmp/naabu.zip \
    && unzip -q /tmp/naabu.zip -d /usr/local/bin naabu \
    && chmod +x /usr/local/bin/naabu \
    # Cleanup
    && rm -f /tmp/subfinder.zip /tmp/httpx.zip /tmp/naabu.zip

# --------------------------------------------------------------------------- #
# Application source
# --------------------------------------------------------------------------- #
COPY src/ ./src/

# --------------------------------------------------------------------------- #
# Runtime configuration
# --------------------------------------------------------------------------- #
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FARO_ENV=production

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
