"""Alembic migrations for the control-plane database."""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config

HERE = Path(__file__).parent


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(HERE))
    if url:
        cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(url: str | None = None, revision: str = "head") -> None:
    from alembic import command

    command.upgrade(alembic_config(url), revision)
