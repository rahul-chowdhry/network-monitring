from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="admin_user"
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    mac_address: Mapped[str | None] = mapped_column(
        String(17), unique=True, nullable=True
    )
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(100), nullable=True)

    status: Mapped[str] = mapped_column(
        Enum("online", "offline", "unknown"),
        default="unknown",
        nullable=False,
    )

    trusted: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    latency_ms: Mapped[float | None] = mapped_column(
        Numeric(10, 2), nullable=True
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    discovery_source: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    discovery_confidence: Mapped[float | None] = mapped_column(
        Numeric(5, 2), nullable=True
    )

    hostname_source: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    vendor_source: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    device_type_source: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    is_estimated: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    ips: Mapped[list["DeviceIP"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
    )

    ports: Mapped[list["DevicePort"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
    )

    events: Mapped[list["DeviceEvent"]] = relationship(
        back_populates="device",
    )

    blocked_records: Mapped[list["BlockedDevice"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
    )


class DeviceIP(Base):
    __tablename__ = "device_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)

    address_family: Mapped[str] = mapped_column(
        Enum("ipv4", "ipv6"),
        nullable=False,
    )

    is_current: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    source: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    device: Mapped["Device"] = relationship(back_populates="ips")

    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "ip_address",
            name="uq_device_ips_device_ip",
        ),
        Index("idx_device_ips_ip", "ip_address"),
        Index("idx_device_ips_current", "is_current"),
    )


class DevicePort(Base):
    __tablename__ = "device_ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    port_number: Mapped[int] = mapped_column(
        Integer, nullable=False
    )

    protocol: Mapped[str] = mapped_column(
        Enum("tcp", "udp"),
        nullable=False,
    )

    state: Mapped[str | None] = mapped_column(
        String(30), nullable=True
    )
    service: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    product: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    version: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    source: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    device: Mapped["Device"] = relationship(back_populates="ports")

    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "port_number",
            "protocol",
            name="uq_device_ports_device_port_protocol",
        ),
        Index("idx_device_ports_port", "port_number"),
        Index("idx_device_ports_state", "state"),
    )


class DeviceEvent(Base):
    __tablename__ = "device_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )

    severity: Mapped[str] = mapped_column(
        Enum("info", "warning", "critical"),
        default="info",
        nullable=False,
    )

    message: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    event_data: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    device: Mapped["Device | None"] = relationship(
        back_populates="events"
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    status: Mapped[str] = mapped_column(
        Enum("running", "completed", "failed"),
        default="running",
        nullable=False,
    )

    subnet: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    devices_found: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )


class Setting(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    setting_key: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False
    )

    setting_value: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    is_sensitive: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class BlockedDevice(Base):
    __tablename__ = "blocked_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    block_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )

    provider: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    provider_rule_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    status: Mapped[str] = mapped_column(
        Enum("requested", "active", "failed", "removed"),
        default="requested",
        nullable=False,
    )

    reason: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    blocked_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    unblocked_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    device: Mapped["Device"] = relationship(
        back_populates="blocked_records"
    )


class RouterIntegration(Base):
    __tablename__ = "router_integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    provider: Mapped[str] = mapped_column(
        String(100), nullable=False
    )

    name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    host: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    username: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    credential_reference: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    status: Mapped[str] = mapped_column(
        Enum(
            "not_configured",
            "connected",
            "error",
            "unsupported",
        ),
        default="not_configured",
        nullable=False,
    )

    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    admin_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("admin_users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
    )

    action: Mapped[str] = mapped_column(
        String(100), nullable=False
    )

    target_type: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    target_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    details: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    admin_user: Mapped["AdminUser | None"] = relationship(
        back_populates="audit_logs"
    )