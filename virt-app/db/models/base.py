"""Shared declarative base and metadata configuration."""

from __future__ import annotations

import re
from typing import ClassVar

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, declared_attr

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _camel_to_snake(name: str) -> str:
    words = re.findall(r"[A-Z0-9]+(?=$|[A-Z][a-z0-9])|[A-Za-z0-9]+", name)
    return "_".join(word.lower() for word in words)


class Base(DeclarativeBase):
    """Declarative base that provides snake_case table names by default."""

    metadata = metadata
    __tablename__: ClassVar[str]

    @declared_attr.directive
    def __tablename__(cls) -> str:  # type: ignore[override]
        return _camel_to_snake(cls.__name__)


__all__ = ["Base", "metadata", "NAMING_CONVENTION"]
