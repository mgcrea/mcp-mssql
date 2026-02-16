# Build stage
FROM python:3.13-alpine AS builder

# Install build dependencies for pymssql (requires freetds)
RUN apk add --no-cache \
    gcc \
    musl-dev \
    freetds-dev

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.12 /uv /uvx /bin/

WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-editable --compile-bytecode

# Copy the project into the intermediate image
ADD . /app

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable --compile-bytecode

# Runtime stage
FROM python:3.13-alpine

# Install runtime dependencies for pymssql
RUN apk add --no-cache freetds

WORKDIR /app

# Copy the environment
COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY pyproject.toml ./

# Build metadata
ARG GIT_COMMIT=unknown
ARG GIT_COMMIT_SHORT=unknown
ARG GIT_COMMIT_DATE=unknown

ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_COMMIT_SHORT=${GIT_COMMIT_SHORT}
ENV GIT_COMMIT_DATE=${GIT_COMMIT_DATE}
ENV PYTHONOPTIMIZE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

CMD ["/app/.venv/bin/mcp-mssql"]
