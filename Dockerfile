# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="matazero" \
      org.opencontainers.image.description="Evidence-grade, ethical image intelligence toolkit for OSINT and digital forensics" \
      org.opencontainers.image.url="https://github.com/nextboxis/matazero" \
      org.opencontainers.image.source="https://github.com/nextboxis/matazero" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/matauser/.local/bin:${PATH}"

# Install minimal runtime libraries for Pillow and native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg62-turbo \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for safe forensic execution
RUN groupadd -g 10001 matauser && \
    useradd -u 10001 -g matauser -s /bin/bash -m matauser && \
    mkdir -p /evidence /home/matauser/.mata /app && \
    chown -R matauser:matauser /evidence /home/matauser /app

WORKDIR /app

# Install dependencies first for layer caching
COPY --chown=matauser:matauser requirements.txt pyproject.toml setup.py README.md ./
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and package data
COPY --chown=matauser:matauser imgint/ ./imgint/
COPY --chown=matauser:matauser matazero/ ./matazero/
COPY --chown=matauser:matauser mata/ ./mata/
COPY --chown=matauser:matauser docs/ ./docs/

# Install the matazero package
RUN pip install --no-cache-dir .

USER matauser
WORKDIR /evidence

VOLUME ["/evidence"]

ENTRYPOINT ["matazero"]
CMD ["--help"]
