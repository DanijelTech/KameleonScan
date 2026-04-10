# w3af - Web Application Attack and Audit Framework
# Modernized Dockerfile with Python 3 support
#
# This Dockerfile is optimized for modern Python 3.11+ and includes
# all necessary dependencies for the w3af security scanner.

FROM python:3.11-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TERM=xterm-256color

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential \
    git \
    # XML/HTML processing
    libxslt1-dev \
    libxml2-dev \
    # Database
    libsqlite3-dev \
    # YAML support
    libyaml-dev \
    # SSL/TLS
    libssl-dev \
    libffi-dev \
    # Compression
    zlib1g-dev \
    liblz4-dev \
    # Network tools
    curl \
    wget \
    # Node.js for certain plugins (optional)
    nodejs \
    npm \
    # System libraries for Python packages
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY w3af/ ./w3af/
COPY w3af_* ./

# Create executable scripts
RUN chmod +x w3af_console w3af_gui w3af_api

# Create necessary directories
RUN mkdir -p /app/profiles /app/scripts /app/tools /app/result

# Set Python path
ENV PYTHONPATH=/app

# Expose default ports
# 44444 - w3af API
# 5000  - Alternative API port
EXPOSE 44444 5000

# Default command
CMD ["/app/w3af_console"]

# Labels for container metadata
LABEL maintainer="w3af team <info@w3af.org>" \
      description="Web Application Attack and Audit Framework" \
      version="2.0.0"