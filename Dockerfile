# AWS Privilege Escalation Agent - Sandbox Container
# This container provides a safe environment for running the agent

FROM python:3.12-slim

LABEL maintainer="security-team"
LABEL description="AWS Privilege Escalation Agent Sandbox"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    groff \
    less \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf aws awscliv2.zip

# Create non-root user for security
RUN useradd -m -s /bin/bash agent
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install security tools
RUN pip install --no-cache-dir \
    pacu \
    principalmapper \
    cloudsplaining \
    scoutsuite

# Copy application code
COPY . .

# Set ownership
RUN chown -R agent:agent /app

# Switch to non-root user
USER agent

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AWS_PRIVESC_SANDBOX=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import aws_privesc_agent; print('OK')"

# Default command
ENTRYPOINT ["python", "-m", "aws_privesc_agent.cli"]
CMD ["--help"]
