from os import getenv
from alembic import context
from sqlmodel import SQLModel, create_engine

# imports for Alembic to detect models
from galactic_router.router.static import Registration  # noqa: F401


def run_migrations() -> None:
    db_engine = context.config.attributes.get(
        'connection',
        create_engine(
            getenv(
                'DB_URL',
                'sqlite:///../galactic-router.db'
            )
        )
    )
    with db_engine.begin() as connection:
        context.configure(
            connection=connection,
            target_metadata=SQLModel.metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations()
