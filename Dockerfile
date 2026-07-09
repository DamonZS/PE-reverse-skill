FROM python:3.11-slim

LABEL org.opencontainers.image.title="reverse-analyzer"
LABEL org.opencontainers.image.description="PentAGI migration scaffold for CLI-based reverse analysis"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REVERSE_ANALYZER_WORKSPACE=/workspace \
    REVERSE_ANALYZER_KNOWLEDGE_DIR=/workspace/.reverse_analyzer/knowledge \
    REVERSE_ANALYZER_SESSIONS_DIR=/workspace/.reverse_analyzer/sessions \
    REVERSE_ANALYZER_REPORTS_DIR=/workspace/reports \
    REVERSE_ANALYZER_DASHBOARD_PORT=8088

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends file binutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY reverse_analyzer ./reverse_analyzer
COPY README.md ./README.md

VOLUME ["/workspace", "/workspace/samples", "/workspace/reports", "/workspace/.reverse_analyzer"]
EXPOSE 8088

ENTRYPOINT ["python", "-m", "reverse_analyzer"]
CMD ["--help"]
