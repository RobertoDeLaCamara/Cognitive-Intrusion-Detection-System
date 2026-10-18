FROM python:3.11-slim AS base

# Injected automatically by `docker buildx build --platform`.
# Defaults to amd64 for classic `docker build` (current CI path, no --platform).
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies come from hashed lock files (requirements.txt + torch 2.6.0, which
# fixes CVE-2025-32434); regenerate them with scripts/lock_requirements.sh.
#   amd64  → torch 2.6.0+cpu from the PyTorch CPU index (smaller wheel)
#   arm64  → torch 2.6.0 from PyPI (manylinux aarch64 wheel, CPU-only)
#   arm/v7 → no official wheel; install requirements.txt unlocked and
#            FTTransformerEngine degrades to RF fallback
COPY requirements.txt requirements-lock-*.txt ./
RUN if [ "$TARGETARCH" = "amd64" ] || [ "$TARGETARCH" = "arm64" ]; then \
        pip install --no-cache-dir --timeout=300 --retries=5 --require-hashes \
            -r requirements-lock-${TARGETARCH}.txt ; \
    else \
        echo "TARGETARCH=${TARGETARCH}: no torch wheel — FTTransformerEngine will degrade to RF fallback." ; \
        pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt ; \
    fi

COPY . .

RUN useradd -m -u 1000 ids
RUN mkdir -p models data && chown ids:ids models data

EXPOSE 8000

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

USER ids

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ── Dashboard target ─────────────────────────────────────────────────────────
FROM base AS dashboard

USER root
COPY requirements-dashboard.txt .
RUN pip install --no-cache-dir -r requirements-dashboard.txt
USER ids

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
