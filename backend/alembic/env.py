"""Alembic environment.

The database URL comes from application settings, so no path or credential is
hardcoded in alembic.ini. A URL set programmatically (for example by a test
that migrates a temporary database) takes precedence.

``render_as_batch`` is required: SQLite cannot ALTER columns in place, so later
migrations rebuild tables (create copy, move rows, DROP old, rename).

Foreign-key enforcement is deliberately left OFF here (SQLite's default for a
new connection). With ``PRAGMA foreign_keys=ON``, the DROP in a batch rebuild
performs an implicit DELETE that fires ON DELETE CASCADE / SET NULL, which would
delete every session and erase audit attribution whenever ``users`` is rebuilt.
The application's own engine enables enforcement; migrations must not.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Importing the models package registers every table on Base.metadata.
import app.models  # noqa: F401
from app.database.base import Base

config = context.config

if config.config_file_name is not None:
    # Keep application loggers alive when migrations run in-process (tests).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

if not config.get_main_option("sqlalchemy.url"):
    from app.core.config import get_settings
    from app.database.session import resolve_database_path

    config.set_main_option(
        "sqlalchemy.url", f"sqlite:///{resolve_database_path(get_settings())}"
    )

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL without connecting."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and apply migrations.

    Nothing is executed on the connection before ``context.configure()``. Under
    SQLAlchemy 2.0 any statement autobegins a transaction, and Alembic would
    then treat it as externally managed and never commit the version stamp.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
