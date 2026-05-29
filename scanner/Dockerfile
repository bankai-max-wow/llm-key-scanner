FROM python:3.11-slim

WORKDIR /app

# Install minimal system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner modules
COPY *.py .

# Run as non-root for security
RUN useradd -m scanner
USER scanner

# Default command
CMD ["python", "orchestrator.py"]
