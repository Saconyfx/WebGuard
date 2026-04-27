# ────────────────────────────────────────────────────────────────
# WebGuard — All-in-one Docker image
# Includes file/code scanners: Semgrep + Bandit + Gitleaks + detect-secrets
# Includes URL scanners:       httpx + Nikto + Nuclei + sqlmap + XSStrike
# ────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    GITLEAKS_VERSION=8.21.2 \
    NUCLEI_VERSION=3.3.5

# ─── System deps ───────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git unzip \
        perl libnet-ssleay-perl libwhisker2-perl libio-socket-ssl-perl libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# ─── Gitleaks (Go binary from GitHub) ──────────────────────────
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# ─── Nuclei (Go binary from GitHub) ────────────────────────────
RUN curl -sSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# ─── Nikto (Perl, clone from GitHub) ───────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# ─── sqlmap (Python, clone from GitHub) ────────────────────────
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# ─── XSStrike (Python, clone from GitHub) ──────────────────────
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike \
    && pip install -r /opt/xsstrike/requirements.txt \
    && printf '#!/bin/sh\nexec python3 /opt/xsstrike/xsstrike.py "$@"\n' > /usr/local/bin/xsstrike \
    && chmod +x /usr/local/bin/xsstrike

# ─── Python deps for the backend ───────────────────────────────
WORKDIR /app
COPY function/requirements.txt /app/function/requirements.txt
RUN pip install -r /app/function/requirements.txt

# ─── Pre-warm Nuclei templates so first scan isn't slow ────────
RUN nuclei -update-templates -silent 2>/dev/null || true

# ─── Copy app code ─────────────────────────────────────────────
COPY frontend /app/frontend
COPY function /app/function

# ─── Runtime user (don't run as root) ──────────────────────────
RUN useradd --create-home --shell /bin/bash webguard \
    && mkdir -p /tmp/webguard /home/webguard/.config/nuclei \
    && cp -r /root/nuclei-templates /home/webguard/ 2>/dev/null || true \
    && chown -R webguard:webguard /app /tmp/webguard /home/webguard
USER webguard

WORKDIR /app/function
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
