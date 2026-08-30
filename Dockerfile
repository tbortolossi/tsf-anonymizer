FROM python:3.11-slim

WORKDIR /app

# Copy source before the editable install: the editable finder maps what it
# can see at install time.
COPY pyproject.toml /app/
COPY tsf_anonymizer/ /app/tsf_anonymizer/
RUN pip install --no-cache-dir -e /app

# /data holds uploads, extracted trees and outputs. The container runs as an
# unprivileged user so files written through the bind mount stay deletable by
# the host user (see docker-compose.yml `user:`).
RUN mkdir -p /data && chmod 0777 /data
ENV TSF_DATA_DIR=/data
VOLUME ["/data"]

EXPOSE 8090
# The probe is a normal client: it authenticates, and speaks TLS when the
# server does (see `tsf-anonymizer healthcheck`).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["tsf-anonymizer", "healthcheck", "--port", "8090"]

# Serving policy (TLS wiring, warnings when a port is exposed unprotected)
# lives in the CLI, so the container and a bare `tsf-anonymizer serve` behave
# the same way.
CMD ["tsf-anonymizer", "serve", "--host", "0.0.0.0", "--port", "8090", "--data-dir", "/data"]
