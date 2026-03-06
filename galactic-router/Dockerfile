FROM python:3

RUN mkdir /workspace
WORKDIR /workspace

COPY galactic_router galactic_router
COPY alembic alembic
COPY pyproject.toml .

RUN pip install -e .

ENTRYPOINT ["galactic-router"]
