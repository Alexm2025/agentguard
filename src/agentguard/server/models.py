"""Database models. Every tenant-owned row carries ``org_id`` and every query filters on it."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from agentguard.core.types import new_id


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(AsyncAttrs, DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


def _id(prefix: str) -> Mapped[str]:
    return mapped_column(String(40), primary_key=True, default=lambda: new_id(prefix)[:40])


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = _id("org_")
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug"),)
    id: Mapped[str] = _id("prj_")
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _id("usr_")
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str | None] = mapped_column(String(300), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(300), nullable=True, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id"),)
    id: Mapped[str] = _id("mem_")
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20))  # admin | analyst | viewer
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebSession(Base):
    __tablename__ = "web_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the cookie token
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = _id("key_")
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("org_id", "name"),)
    id: Mapped[str] = _id("pol_")
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    name: Mapped[str] = mapped_column(String(100))
    active_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "revision"),)
    id: Mapped[str] = _id("pv_")
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(String(40), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    yaml: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(64))
    comment: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_org_ts", "org_id", "timestamp"),
        Index("ix_events_org_action", "org_id", "action"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(40))
    project_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(40))
    source: Mapped[str] = mapped_column(String(40), default="sdk")
    tool: Mapped[str | None] = mapped_column(String(200), nullable=True)
    action: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk: Mapped[str | None] = mapped_column(String(20), nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (Index("ix_approvals_org_status", "org_id", "status"),)
    id: Mapped[str] = _id("apr_")
    org_id: Mapped[str] = mapped_column(String(40))
    project_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    event_id: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(200))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # scrubbed decision event
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str] = mapped_column(String(1000), default="")
    channel: Mapped[str | None] = mapped_column(String(40), nullable=True)


class FalsePositiveReport(Base):
    __tablename__ = "false_positive_reports"
    id: Mapped[str] = _id("fp_")
    org_id: Mapped[str] = mapped_column(String(40), index=True)
    event_id: Mapped[str] = mapped_column(String(64))
    reporter: Mapped[str] = mapped_column(String(200))
    note: Mapped[str] = mapped_column(String(2000), default="")
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Append-only, hash-chained per organisation: hash = sha256(prev_hash || canonical(entry))."""

    __tablename__ = "audit_log"
    __table_args__ = (UniqueConstraint("org_id", "seq"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(40), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
