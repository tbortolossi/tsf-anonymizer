# Two stages: uv resolves and installs from uv.lock into a self-contained
# virtual environment, the runtime image carries only that environment.
FROM python:3.14-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app
# Sources before the sync: the package itself is part of the install.
COPY pyproject.toml uv.lock README.md LICENSE /app/
COPY tsf_anonymizer/ /app/tsf_anonymizer/
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.14-slim
LABEL org.opencontainers.image.title="tsf-anonymizer" \
      org.opencontainers.image.description="Anonymize PAN-OS tech support files and prove, by an independent comparison, that nothing but identifiers was lost." \
      org.opencontainers.image.source="https://github.com/tbortolossi/tsf-anonymizer" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    TSF_DATA_DIR=/data
# /data holds uploads, extracted trees and outputs. The container runs as an
# unprivileged user so files written through the bind mount stay deletable by
# the host user (see docker-compose.yml `user:`).
RUN mkdir -p /data && chmod 0777 /data
VOLUME ["/data"]
WORKDIR /data

EXPOSE 8090
# The probe is a normal client: it authenticates, and speaks TLS when the
# server does (see `tsf-anonymizer healthcheck`).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["tsf-anonymizer", "healthcheck", "--port", "8090"]

# Serving policy (TLS wiring, warnings when a port is exposed unprotected)
# lives in the CLI, so the container and a bare `tsf-anonymizer serve` behave
# the same way.
CMD ["tsf-anonymizer", "serve", "--host", "0.0.0.0", "--port", "8090", "--data-dir", "/data"]
