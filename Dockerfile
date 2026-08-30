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
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/health', timeout=3).status==200 else 1)"

CMD ["python", "-m", "uvicorn", "--factory", "tsf_anonymizer.web.app:create_app", \
     "--host", "0.0.0.0", "--port", "8090", "--timeout-keep-alive", "120"]
