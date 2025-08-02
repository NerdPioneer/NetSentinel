# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies required for network analysis
RUN apt-get update && apt-get install -y \
    # Network tools and libraries
    libpcap-dev \
    tcpdump \
    wireshark-common \
    tshark \
    # Build tools for Python packages
    gcc \
    g++ \
    make \
    # System utilities
    net-tools \
    iproute2 \
    iputils-ping \
    curl \
    wget \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash netsentinel && \
    usermod -a -G wireshark netsentinel

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Install NetSentinel in development mode
RUN pip install -e .

# Create directories for data and logs
RUN mkdir -p /app/data /app/logs /app/output && \
    chown -R netsentinel:netsentinel /app

# Switch to non-root user
USER netsentinel

# Expose port for potential web interface
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import netsentinel; print('NetSentinel is healthy')" || exit 1

# Default command - can be overridden
CMD ["python", "-m", "netsentinel.main", "--help"]
