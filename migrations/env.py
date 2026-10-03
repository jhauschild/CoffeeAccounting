"""Alembic environment.

Database URL precedence: `-x url=...` > `config.attributes["url"]` > `sqlalchemy.url` in
alembic.ini > `DATABASE_URL` from app settings. Uses the app's engine factory so SQLite
pragmas (foreign keys, WAL, busy timeout) apply to migrations as well.
"""

from logging.config import fileConfig

from alembic import context

from app.config import get_settings
from app.db import make_engine
from app.models import Base

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    return (
        context.get_x_argument(as_dictionary=True).get("url")
        or config.attributes.get("url")
        or config.get_main_option("sqlalchemy.url")
        or get_settings().database_url
    )


def _include_object(obj, name, type_, reflected, compare_to):
    # The effective_users view is managed by hand in the migration.
    return not (type_ == "table" and name == "effective_users")


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(_url())
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,
                include_object=_include_object,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
