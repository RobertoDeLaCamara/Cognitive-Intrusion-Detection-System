FROM python:3.11-slim AS base

# Injected automatically by `docker buildx build --platform`.
# Defaults to amd64 for classic `docker build` (current CI path, no --platform).
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Torch wheel source differs by architecture:
#   amd64  → PyTorch CPU index (explicit +cpu build, smaller wheel)
#   arm64  → PyPI standard index (manylinux2014_aarch64 wheel for 2.5.1)
#   arm/v7 → no official wheel; FTTransformerEngine degrades to RF fallback
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        pip install --no-cache-dir torch==2.5.1+cpu \
            --index-url https://download.pytorch.org/whl/cpu ; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        pip install --no-cache-dir torch==2.5.1 ; \
    else \
        echo "TARGETARCH=${TARGETARCH}: no torch wheel — FTTransformerEngine will degrade to RF fallback." ; \
    fi

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

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
