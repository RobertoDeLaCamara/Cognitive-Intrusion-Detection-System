FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install torch CPU with pinned version
RUN pip install --no-cache-dir torch==2.5.1+cpu --index-url https://download.pytorch.org/whl/cpu

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
