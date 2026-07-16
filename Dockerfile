FROM python:3.12-slim

WORKDIR /app

# Install the package from pyproject metadata (no requirements.txt)
COPY pyproject.toml README.md ./
COPY sentinel_v/ ./sentinel_v/
RUN pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir ".[cli]"

# Default configuration (mount your own over /app/config to override)
COPY config/ ./config/

RUN mkdir -p /app/logs /app/data

# Non-root runtime user
RUN useradd -m -u 1000 sentinel && \
    chown -R sentinel:sentinel /app
USER sentinel

# NOTE: `sentinel-v start` runs a foreground process and does not open
# a network port, so there is no meaningful TCP healthcheck; container
# exit is the failure signal.

CMD ["sentinel-v", "start", "--config", "/app/config/sentinel.default.yaml"]
