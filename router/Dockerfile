FROM python:3.13-slim AS builder

WORKDIR /build

COPY README.md pyproject.toml ./
COPY galactic_router ./galactic_router

RUN python -m pip install --no-cache-dir --upgrade pip build && \
    python -m build --wheel

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /workspace

RUN addgroup --system galactic && \
    adduser --system --ingroup galactic --home /workspace galactic && \
    mkdir -p /workspace/data && \
    chown -R galactic:galactic /workspace

COPY --from=builder /build/dist/*.whl /tmp/
COPY alembic ./alembic
COPY README.md pyproject.toml ./

RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir /tmp/*.whl && \
    rm -f /tmp/*.whl

USER galactic

ENTRYPOINT ["galactic-router"]
