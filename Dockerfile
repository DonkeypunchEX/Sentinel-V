FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinel_v ./sentinel_v
RUN pip install --no-cache-dir -e ".[ml,intel]"
EXPOSE 8787
CMD ["uvicorn", "sentinel_v.api.app:app", "--host", "0.0.0.0", "--port", "8787"]
