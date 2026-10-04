# Stage 1: Build dependencies and wheels
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Minimal runtime image
FROM python:3.11-slim AS runtime

LABEL maintainer="Security Engineering Team"
LABEL description="Enterprise Cryptographic Discovery & CycloneDX 1.6 CBOM Generator"

# Install runtime utilities (ripgrep for fast regex search, OpenSSL for binary/cert inspection, Nmap for network recon, Node.js for Web Visualizer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ripgrep \
    openssl \
    ca-certificates \
    nmap \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy application source and configurations
COPY pyproject.toml .
COPY cbom_policy.json .
COPY crypto_policy_rules.json .
COPY package.json .
COPY web/ ./web/
COPY spectra/ ./spectra/

# Install Node dependencies for web visualizer
RUN npm install --omit=dev

# Install spectra as an editable package into /opt/venv
RUN pip install --no-cache-dir -e .

# Expose web visualizer port
EXPOSE 3000

# Create runner user
RUN useradd -u 10001 -m appuser && \
    chown -R appuser:appuser /app /opt/venv

# Run as root by default so spectra can scan mounted host filesystems without permission errors
USER root

ENTRYPOINT ["spectra"]
CMD ["--help"]
