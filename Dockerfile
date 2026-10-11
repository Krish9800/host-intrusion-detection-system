# Multi-stage Rootless Dockerfile for Host Intrusion Detection System (HIDS)
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip && \
    pip install .

# Final runtime image
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HIDS_ENVIRONMENT=production \
    HIDS_DB_PATH=/var/lib/hids/hids.db

WORKDIR /app

# Create unprivileged user (UID 10001) and hids data directories
RUN groupadd -g 10001 hids && \
    useradd -u 10001 -g hids -s /bin/false -M hids && \
    mkdir -p /var/lib/hids /app/data && \
    chown -R hids:hids /var/lib/hids /app/data

# Copy installed dependencies and source from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/hids /usr/local/bin/hids
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY src/ ./src/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

ENTRYPOINT ["uvicorn", "hids.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
