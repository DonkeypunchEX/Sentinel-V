FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinel_v ./sentinel_v
COPY rules ./rules
COPY playbooks ./playbooks
# pg extra pulls psycopg for the Compose Postgres URL (SENTINEL_DB_URL).
RUN pip install --no-cache-dir -e ".[ml,intel,pg]"
# Run as an unprivileged user, not root.
RUN useradd --system --create-home --uid 10001 sentinel && chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 8787
CMD ["uvicorn", "sentinel_v.api.app:app", "--host", "0.0.0.0", "--port", "8787"]
