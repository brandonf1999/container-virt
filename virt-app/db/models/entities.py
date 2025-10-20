"""ORM models representing the initial persistence schema."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    Boolean,
    BigInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class HostStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"


class DomainState(str, Enum):
    RUNNING = "running"
    BLOCKED = "blocked"
    PAUSED = "paused"
    SHUTDOWN = "shutdown"
    SHUTOFF = "shutoff"
    CRASHED = "crashed"
    PMSUSPENDED = "pmsuspended"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StorageDomainType(str, Enum):
    DIR = "dir"
    FS = "fs"
    NETFS = "netfs"
    LOGICAL = "logical"
    ISCSI = "iscsi"
    GLUSTER = "gluster"
    RBD = "rbd"
    SHEEPDOG = "sheepdog"
    ZFS = "zfs"
    UNKNOWN = "unknown"


class HostStorageScope(str, Enum):
    LOCAL = "local"
    SHARED = "shared"


class HostStorageStatusState(str, Enum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    MISSING = "missing"


class HostNetworkStatusState(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    MISSING = "missing"


class Cluster(Base):
    """Physical or logical grouping of libvirt hosts."""

    __tablename__ = "clusters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    connection_uri: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    hosts: Mapped[list["Host"]] = relationship(
        back_populates="cluster",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Host(Base):
    """Individual libvirt host managed within a cluster."""

    __tablename__ = "hosts"

    __table_args__ = (
        UniqueConstraint("cluster_id", "libvirt_id", name="uq_hosts_cluster_libvirt_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("clusters.id", ondelete="CASCADE"),
        nullable=False,
    )
    libvirt_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[HostStatus] = mapped_column(
        SAEnum(HostStatus, name="host_status", validate_strings=True),
        default=HostStatus.OFFLINE,
        nullable=False,
    )
    facts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    cluster: Mapped[Cluster] = relationship(back_populates="hosts")
    domains: Mapped[list["Domain"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    tasks: Mapped[list["Task"]] = relationship(back_populates="host")
    storage_statuses: Mapped[list["HostStorageStatus"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    network_statuses: Mapped[list["HostNetworkStatus"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Domain(Base):
    """Tracked libvirt domain with cached runtime characteristics."""

    __tablename__ = "domains"

    __table_args__ = (
        UniqueConstraint("host_id", "uuid", name="uq_domains_host_uuid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[DomainState] = mapped_column(
        SAEnum(DomainState, name="domain_state", validate_strings=True),
        default=DomainState.UNKNOWN,
        nullable=False,
    )
    state_code: Mapped[Optional[int]] = mapped_column(Integer)
    persistent: Mapped[Optional[bool]] = mapped_column(Boolean)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    vcpu_count: Mapped[Optional[int]] = mapped_column(Integer)
    memory_mb: Mapped[Optional[int]] = mapped_column(Integer)
    metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    guest_agent_ips: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    raw_xml: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    host: Mapped[Host] = relationship(back_populates="domains")
    console_sessions: Mapped[list["ConsoleSession"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    tasks: Mapped[list["Task"]] = relationship(back_populates="domain")


class ConsoleSession(Base):
    """Issued console session tokens for websocket/API access."""

    __tablename__ = "console_sessions"

    __table_args__ = (
        UniqueConstraint("token", name="uq_console_sessions_token"),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_console_sessions_expiration_order",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
    )
    token: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )

    domain: Mapped[Domain] = relationship(back_populates="console_sessions")


class Task(Base):
    """Queued background work scoped to hosts or domains."""

    __tablename__ = "tasks"

    __table_args__ = (
        Index("ix_tasks_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    type: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[TaskStatus] = mapped_column(
        SAEnum(TaskStatus, name="task_status", validate_strings=True),
        default=TaskStatus.PENDING,
        nullable=False,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    host_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.id", ondelete="SET NULL"),
    )
    domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="SET NULL"),
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    host: Mapped[Optional[Host]] = relationship(back_populates="tasks")
    domain: Mapped[Optional[Domain]] = relationship(back_populates="tasks")


Index(
    "ix_hosts_status",
    Host.status,
)

Index(
    "ix_domains_state",
    Domain.state,
)

Index(
    "ix_console_sessions_active",
    ConsoleSession.token,
    unique=True,
    postgresql_where=ConsoleSession.revoked_at.is_(None),
)


class StorageDomain(Base):
    """Normalized libvirt storage domain definition."""

    __tablename__ = "storage_domains"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[StorageDomainType] = mapped_column(
        SAEnum(StorageDomainType, name="storage_domain_type", validate_strings=True),
        default=StorageDomainType.UNKNOWN,
        nullable=False,
    )
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_host: Mapped[Optional[str]] = mapped_column(String(255))
    source_path: Mapped[Optional[str]] = mapped_column(String(1024))
    source_name: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(String(512))
    options: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    host_statuses: Mapped[list["HostStorageStatus"]] = relationship(
        back_populates="storage_domain",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


Index(
    "uq_storage_domains_shared",
    StorageDomain.name,
    StorageDomain.type,
    unique=True,
    postgresql_where=StorageDomain.is_shared.is_(True),
)


class HostStorageStatus(Base):
    """Per-host availability snapshot for a storage domain."""

    __tablename__ = "host_storage_status"

    __table_args__ = (
        UniqueConstraint("host_id", "storage_domain_id", name="uq_host_storage"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    storage_domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("storage_domains.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope: Mapped[HostStorageScope] = mapped_column(
        SAEnum(HostStorageScope, name="host_storage_scope", validate_strings=True),
        nullable=False,
    )
    status: Mapped[HostStorageStatusState] = mapped_column(
        SAEnum(HostStorageStatusState, name="host_storage_status_state", validate_strings=True),
        default=HostStorageStatusState.MISSING,
        nullable=False,
    )
    capacity_bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    allocation_bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    available_bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    message: Mapped[Optional[str]] = mapped_column(String(512))
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )

    host: Mapped[Host] = relationship(back_populates="storage_statuses")
    storage_domain: Mapped[StorageDomain] = relationship(back_populates="host_statuses")


class Network(Base):
    """Normalized libvirt network definition."""

    __tablename__ = "networks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    forward_mode: Mapped[Optional[str]] = mapped_column(String(64))
    bridge_name: Mapped[Optional[str]] = mapped_column(String(255))
    vlan_id: Mapped[Optional[int]] = mapped_column(Integer)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(512))
    options: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    host_statuses: Mapped[list["HostNetworkStatus"]] = relationship(
        back_populates="network",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


Index(
    "uq_networks_shared",
    Network.name,
    unique=True,
    postgresql_where=Network.is_shared.is_(True),
)


class HostNetworkStatus(Base):
    """Per-host status snapshot for a libvirt network."""

    __tablename__ = "host_network_status"

    __table_args__ = (
        UniqueConstraint("host_id", "network_id", name="uq_host_network"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
    )
    network_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("networks.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[HostNetworkStatusState] = mapped_column(
        SAEnum(HostNetworkStatusState, name="host_network_status_state", validate_strings=True),
        default=HostNetworkStatusState.MISSING,
        nullable=False,
    )
    bridge_active: Mapped[Optional[bool]] = mapped_column(Boolean)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    mac_prefix: Mapped[Optional[str]] = mapped_column(String(32))
    message: Mapped[Optional[str]] = mapped_column(String(512))
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )

    host: Mapped[Host] = relationship(back_populates="network_statuses")
    network: Mapped[Network] = relationship(back_populates="host_statuses")


__all__ = [
    "Cluster",
    "ConsoleSession",
    "Domain",
    "DomainState",
    "Host",
    "HostStatus",
    "Task",
    "TaskStatus",
    "StorageDomain",
    "StorageDomainType",
    "HostStorageStatus",
    "HostStorageScope",
    "HostStorageStatusState",
    "Network",
    "HostNetworkStatus",
    "HostNetworkStatusState",
]
