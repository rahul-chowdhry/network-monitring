from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# =========================
# Admin / Authentication
# =========================

class AdminUserBase(BaseModel):
    username: str = Field(min_length=3, max_length=100)


class AdminUserCreate(AdminUserBase):
    password: str = Field(min_length=8, max_length=255)


class AdminUserLogin(BaseModel):
    username: str
    password: str


class AdminUserResponse(AdminUserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# =========================
# Device
# =========================

class DeviceIPResponse(BaseModel):
    id: int
    ip_address: str
    address_family: str
    is_current: bool
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str | None = None

    model_config = ConfigDict(from_attributes=True)


class DevicePortResponse(BaseModel):
    id: int
    port_number: int
    protocol: str
    state: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str | None = None

    model_config = ConfigDict(from_attributes=True)


class DeviceEventResponse(BaseModel):
    id: int
    event_type: str
    severity: str
    message: str
    event_data: dict | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeviceResponse(BaseModel):
    id: int
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    status: str
    trusted: bool
    latency_ms: float | None = None

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    discovery_source: str | None = None
    discovery_confidence: float | None = None

    hostname_source: str | None = None
    vendor_source: str | None = None
    device_type_source: str | None = None

    is_estimated: bool
    notes: str | None = None

    created_at: datetime
    updated_at: datetime

    ips: list[DeviceIPResponse] = []
    ports: list[DevicePortResponse] = []

    model_config = ConfigDict(from_attributes=True)


class DeviceTrustUpdate(BaseModel):
    trusted: bool


class DeviceNotesUpdate(BaseModel):
    notes: str | None = Field(default=None, max_length=5000)


# =========================
# Device Blocking
# =========================

class BlockDeviceRequest(BaseModel):
    block_type: str = Field(min_length=1, max_length=50)
    reason: str | None = Field(default=None, max_length=255)


class BlockedDeviceResponse(BaseModel):
    id: int
    device_id: int
    block_type: str
    provider: str | None = None
    provider_rule_id: str | None = None
    status: str
    reason: str | None = None
    blocked_at: datetime | None = None
    unblocked_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================
# Network Scan
# =========================

class ScanRequest(BaseModel):
    subnet: str | None = Field(
        default=None,
        description="IPv4 CIDR subnet. If omitted, the application detects the local subnet.",
    )
    timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=300,
    )


class ScanRunResponse(BaseModel):
    id: int
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    subnet: str | None = None
    devices_found: int
    error_message: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================
# Settings
# =========================

class SettingResponse(BaseModel):
    id: int
    setting_key: str
    setting_value: str | None = None
    is_sensitive: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SettingUpdate(BaseModel):
    setting_value: str | None = None


# =========================
# Router Integration
# =========================

class RouterIntegrationCreate(BaseModel):
    provider: str = Field(min_length=1, max_length=100)
    name: str | None = Field(default=None, max_length=255)
    enabled: bool = False
    host: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    credential_reference: str | None = Field(
        default=None,
        max_length=255,
    )


class RouterIntegrationResponse(BaseModel):
    id: int
    provider: str
    name: str | None = None
    enabled: bool
    host: str | None = None
    username: str | None = None
    credential_reference: str | None = None
    status: str
    last_checked_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================
# Audit Logs
# =========================

class AuditLogResponse(BaseModel):
    id: int
    admin_user_id: int | None = None
    action: str
    target_type: str | None = None
    target_id: int | None = None
    details: dict | None = None
    ip_address: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================
# Dashboard
# =========================

class DashboardSummary(BaseModel):
    total_devices: int
    online_devices: int
    offline_devices: int
    unknown_devices: int
    trusted_devices: int
    blocked_devices: int
    active_alerts: int


# =========================
# Generic API Responses
# =========================

class MessageResponse(BaseModel):
    message: str


class HealthResponse(BaseModel):
    status: str
    database: str
    nmap: str