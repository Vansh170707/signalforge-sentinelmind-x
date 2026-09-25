FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /uvx /bin/
WORKDIR /app/backend
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 PYTHONUNBUFFERED=1
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ ./
COPY scripts/ /app/scripts/
COPY data/mitre/attack_catalog.json /app/data/mitre/attack_catalog.json
RUN uv sync --frozen --no-dev
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uv", "run", "--no-dev", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
