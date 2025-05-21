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