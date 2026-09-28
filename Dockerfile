FROM ghcr.io/astral-sh/uv:0.12.5 AS uv
FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY --from=uv /uv /uvx /bin/
WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY dataset_builder ./dataset_builder
COPY src ./src
RUN uv sync --frozen --no-dev --no-install-project

COPY config ./config
COPY models ./models
RUN uv sync --frozen --no-dev

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /runtime/zeek /runtime/truth /runtime/predictions \
    && chown -R appuser:appuser /app /runtime

USER appuser
ENTRYPOINT ["uv", "run", "--frozen", "--no-dev"]
