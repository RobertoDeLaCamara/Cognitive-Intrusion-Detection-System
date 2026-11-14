FROM python:3.11-slim AS base

# Injected automatically by `docker buildx build --platform`.
# Defaults to amd64 for classic `docker build` (current CI path, no --platform).
ARG TARGETARCH=amd64

# Runtime needs only the libpcap shared library. On amd64 and arm64 every dependency in the
# lock files installs from a prebuilt wheel, so no compiler goes into the image (it was
# ~250 MB of gcc/g++ and headers). Other architectures install requirements.txt unlocked
# and may have to build from source, so they still get the toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && if [ "$TARGETARCH" != "amd64" ] && [ "$TARGETARCH" != "arm64" ]; then \
        apt-get install -y --no-install-recommends libpcap-dev gcc g++ ; \
    fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies come from hashed lock files (requirements.txt + torch 2.6.0, which
# fixes CVE-2025-32434); regenerate them with scripts/lock_requirements.sh.
#   amd64  → torch 2.6.0+cpu from the PyTorch CPU index (smaller wheel)
#   arm64  → torch 2.6.0 from PyPI (manylinux aarch64 wheel, CPU-only)
#   arm/v7 → no official wheel; install requirements.txt unlocked and
#            FTTransformerEngine degrades to RF fallback
#
# Installed in three layers (torch / numeric stack / rest) instead of one ~390 MB layer:
# the registry on Magua cannot commit a layer that large inside the Docker client's 30 s
# response-header timeout, so the push of a rebuilt dependency layer failed. torch almost
# never changes, so its layer is pushed once and then stays cached; each part has its own
# COPY so changing another dependency does not invalidate it. The parts are generated from
# requirements-lock-<arch>.txt by scripts/split_lock.py (tests/test_lock_split.py keeps them in sync).
COPY requirements-lock-torch-*.txt ./
RUN if [ "$TARGETARCH" = "amd64" ] || [ "$TARGETARCH" = "arm64" ]; then \
        pip install --no-cache-dir --timeout=300 --retries=5 --require-hashes --no-deps \
            -r requirements-lock-torch-${TARGETARCH}.txt ; \
    fi

COPY requirements-lock-sci-*.txt ./
RUN if [ "$TARGETARCH" = "amd64" ] || [ "$TARGETARCH" = "arm64" ]; then \
        pip install --no-cache-dir --timeout=300 --retries=5 --require-hashes --no-deps \
            -r requirements-lock-sci-${TARGETARCH}.txt ; \
    fi

COPY requirements.txt requirements-lock-rest-*.txt ./
RUN if [ "$TARGETARCH" = "amd64" ] || [ "$TARGETARCH" = "arm64" ]; then \
        pip install --no-cache-dir --timeout=300 --retries=5 --require-hashes --no-deps \
            -r requirements-lock-rest-${TARGETARCH}.txt ; \
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

# ARGs do not carry over from the parent stage.
ARG TARGETARCH=amd64

USER root
# Same rule as the base stage: hashed lock on amd64/arm64 (requirements-lock-dashboard.txt,
# resolved on top of the base lock by scripts/lock_requirements.sh), unlocked elsewhere.
COPY requirements-dashboard.txt requirements-lock-dashboard.txt ./
RUN if [ "$TARGETARCH" = "amd64" ] || [ "$TARGETARCH" = "arm64" ]; then \
        pip install --no-cache-dir --timeout=300 --retries=5 --require-hashes --no-deps \
            -r requirements-lock-dashboard.txt ; \
    else \
        pip install --no-cache-dir --timeout=300 --retries=5 -r requirements-dashboard.txt ; \
    fi
USER ids

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
