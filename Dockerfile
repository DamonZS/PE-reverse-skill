FROM node:20-bookworm-slim AS frontend-builder

WORKDIR /src/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM golang:1.26-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/reverse-analyzer-server ./cmd/reverse-analyzer-server


FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="reverse-analyzer"
LABEL org.opencontainers.image.description="Integrated Chinese Web console and loopback workspace API for reverse analysis"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REVERSE_ANALYZER_WORKSPACE=/workspace \
    REVERSE_ANALYZER_KNOWLEDGE_DIR=/workspace/.reverse_analyzer/knowledge \
    REVERSE_ANALYZER_SESSIONS_DIR=/workspace/.reverse_analyzer/sessions \
    REVERSE_ANALYZER_REPORTS_DIR=/workspace/reports \
    REVERSE_ANALYZER_WEB_ADDR=0.0.0.0:8090 \
    REVERSE_ANALYZER_FRONTEND_DIR=/app/frontend/dist

WORKDIR /app

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends file binutils build-essential cmake postgresql-client docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt README.md ./
COPY reverse_analyzer ./reverse_analyzer
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir .

COPY --from=frontend-builder /src/frontend/dist ./frontend/dist
COPY --from=go-builder /out/reverse-analyzer-server /usr/local/bin/reverse-analyzer-server
COPY scripts/platform_backup.py /usr/local/bin/reverse-analyzer-backup
COPY scripts/p11_catalog_audit.py /usr/local/bin/p11-catalog-audit
COPY deploy/platform-entrypoint.sh /usr/local/bin/platform-entrypoint

RUN groupadd --gid 10001 reverse-analyzer \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin reverse-analyzer \
    && mkdir -p /workspace /tmp/reverse-analyzer \
    && chown -R 10001:10001 /workspace /tmp/reverse-analyzer \
    && chmod 0755 /usr/local/bin/reverse-analyzer-backup /usr/local/bin/p11-catalog-audit /usr/local/bin/platform-entrypoint

USER reverse-analyzer

VOLUME ["/workspace", "/workspace/samples", "/workspace/reports", "/workspace/.reverse_analyzer"]
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json,urllib.request; json.load(urllib.request.urlopen('http://127.0.0.1:8090/api/health', timeout=3))" || exit 1

ENTRYPOINT ["platform-entrypoint"]
