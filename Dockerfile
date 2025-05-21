# Use Python 3.11 slim as base image
FROM python:3.11-slim

WORKDIR /app

# Install git and other dependencies
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent security scanner code
COPY . .

# Set the entrypoint
ENTRYPOINT ["python", "-m", "agent_security"]

# Default command to scan examples directory
CMD ["examples"]

# Usage Instructions:
# To scan built-in examples:
#   docker run agent-security
#
# To scan a specific built-in example:
#   docker run agent-security examples/va.yaml
#
# To scan files from your local filesystem:
#   docker run -v $(pwd):/local agent-security /local/path/to/your/file.yaml
#
# To scan a directory from your local filesystem:
#   docker run -v $(pwd):/local agent-security /local/path/to/your/directory 