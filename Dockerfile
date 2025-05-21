# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent security scanner code and examples
COPY . .

# Create examples directory in a location we'll copy from
RUN mkdir -p /examples && cp -r /app/examples/* /examples/

# Final stage using distroless
FROM gcr.io/distroless/python3:nonroot

# Set up working directory and scan directory
WORKDIR /scan

# Copy examples directory
COPY --from=builder /examples /scan/examples

# Copy application code and dependencies
COPY --from=builder /app /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/lib/python3/dist-packages

# Set Python path to find installed packages
ENV PYTHONPATH=/usr/lib/python3/dist-packages:/app

# Add debug environment variable
ENV AGENT_SECURITY_DEBUG=1

# Set the entrypoint
ENTRYPOINT ["python", "-m", "agent_security", "scan"]

# Default command to scan examples directory
CMD ["examples"]

# Usage Instructions:
# To scan built-in examples:
#   docker run agent-security scan examples
#
# To scan a specific built-in example:
#   docker run agent-security scan examples/va.yaml
#
# To scan files from your local filesystem:
#   docker run -v $(pwd):/scan agent-security scan /scan/path/to/your/file.yaml
#
# To scan a directory from your local filesystem:
#   docker run -v $(pwd):/scan agent-security scan /scan/path/to/your/directory 