"""SQLAlchemy ORM models for the Kangal threat-intel platform.

Tables:
- scans: top-level recon run
- assets: discovered entities (domain, subdomain, ip, port, url, ...)
- findings: vulnerabilities / observations correlated to assets
- events: per-stage log entries (also broadcast via Redis pub/sub)

DB-agnostic JSON column: Postgres JSONB in production, JSON elsewhere
(SQLite for local dev / e2e).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import (
    JSON,
    String,
    Integer,
    DateTime,
    ForeignKey,
    Text,
    Index,
    TypeDecorator,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class _JSON(TypeDecorator):
    """Postgres JSONB when available, plain JSON on SQLite/MySQL."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class _UUID(TypeDecorator):
    """Postgres UUID when available, plain String elsewhere."""

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(UUID(as_uuid=False))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        return value

    def process_result_value(self, value, dialect):
        return value


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="active")  # passive|active
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    # queued | running | completed | failed
    current_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(_JSON, nullable=False, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    events: Mapped[list["Event"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(_UUID, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # domain|subdomain|ip|port|service|url|endpoint
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(
        _UUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    meta: Mapped[dict[str, Any]] = mapped_column("meta_json", _JSON, nullable=False, default=dict)
    discovered_by: Mapped[str] = mapped_column(String(64), nullable=False)  # agent name
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="assets")
    children: Mapped[list["Asset"]] = relationship("Asset", backref="parent", remote_side="Asset.id")

    __table_args__ = (
        Index("ix_assets_scan_type_value", "scan_id", "type", "value"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(_UUID, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(_UUID, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(
        _UUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    # critical | high | medium | low | info
    vuln_class: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column("evidence_json", _JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(_UUID, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)  # info|warn|error|success
    message: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    scan: Mapped[Scan] = relationship(back_populates="events")
