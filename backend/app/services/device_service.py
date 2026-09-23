from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Device,
    DeviceEvent,
    DeviceIP,
    DevicePort,
)
from .network_scanner import DiscoveredHost, DiscoveredPort


class DeviceService:
    """
    Synchronizes network scanner results with the database.

    Important:
    - Existing devices are updated instead of duplicated.
    - Unknown information remains NULL.
    - Scanner-derived information is marked with its source.
    - No device is blocked or disconnected by this service.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ============================================================
    # Public API
    # ============================================================

    def sync_hosts(
        self,
        hosts: list[DiscoveredHost],
    ) -> list[Device]:
        """
        Synchronize discovered hosts into the database.
        """

        devices: list[Device] = []

        for host in hosts:
            device = self.sync_host(host)
            devices.append(device)

        self.db.commit()

        return devices

    def sync_host(
        self,
        host: DiscoveredHost,
    ) -> Device:
        """
        Synchronize one discovered host.
        """

        device = self._find_existing_device(host)

        is_new = device is None

        if device is None:
            device = Device(
                mac_address=host.mac_address,
                first_seen=datetime.utcnow(),
            )

            self.db.add(device)
            self.db.flush()

        previous_status = device.status

        # --------------------------------------------------------
        # Basic device information
        # --------------------------------------------------------

        if host.mac_address:
            device.mac_address = host.mac_address

        if host.hostname:
            device.hostname = host.hostname
            device.hostname_source = (
                host.hostname_source or "nmap"
            )

        if host.vendor:
            device.vendor = host.vendor
            device.vendor_source = (
                host.vendor_source or "nmap"
            )

        device.status = (
            "online"
            if host.status == "online"
            else "unknown"
        )

        if host.latency_ms is not None:
            device.latency_ms = Decimal(
                str(host.latency_ms)
            )

        device.discovery_source = (
            host.discovery_source
        )

        device.discovery_confidence = Decimal(
            str(host.discovery_confidence)
        )

        device.is_estimated = (
            host.is_estimated
        )

        now = datetime.utcnow()

        if device.first_seen is None:
            device.first_seen = now

        device.last_seen = now

        # --------------------------------------------------------
        # IP address
        # --------------------------------------------------------

        self._sync_ip(
            device=device,
            ip_address=host.ip_address,
            source=host.discovery_source,
        )

        # --------------------------------------------------------
        # Ports
        # --------------------------------------------------------

        self._sync_ports(
            device=device,
            ports=host.ports,
            source=host.discovery_source,
        )

        self.db.flush()

        # --------------------------------------------------------
        # Events
        # --------------------------------------------------------

        if is_new:
            self._create_event(
                device=device,
                event_type="device_discovered",
                severity="info",
                message=(
                    f"New device discovered at "
                    f"{host.ip_address}"
                ),
                event_data={
                    "ip_address": host.ip_address,
                    "mac_address": host.mac_address,
                    "hostname": host.hostname,
                    "vendor": host.vendor,
                },
            )

        elif previous_status != device.status:
            self._create_event(
                device=device,
                event_type="status_changed",
                severity="info",
                message=(
                    f"Device status changed from "
                    f"{previous_status} to "
                    f"{device.status}"
                ),
                event_data={
                    "previous_status": previous_status,
                    "new_status": device.status,
                    "ip_address": host.ip_address,
                },
            )

        return device

    # ============================================================
    # Device Lookup
    # ============================================================

    def _find_existing_device(
        self,
        host: DiscoveredHost,
    ) -> Device | None:
        """
        Find an existing device using the strongest available
        identity information.

        Priority:
        1. MAC address
        2. Current IP address
        """

        if host.mac_address:
            device = self.db.scalar(
                select(Device).where(
                    Device.mac_address
                    == host.mac_address
                )
            )

            if device is not None:
                return device

        device = self.db.scalar(
            select(Device)
            .join(DeviceIP)
            .where(
                DeviceIP.ip_address
                == host.ip_address
            )
        )

        return device

    # ============================================================
    # IP Synchronization
    # ============================================================

    def _sync_ip(
        self,
        device: Device,
        ip_address: str,
        source: str | None,
    ) -> DeviceIP:
        """
        Add or update the device's current IPv4 address.
        """

        existing_ip = self.db.scalar(
            select(DeviceIP).where(
                DeviceIP.device_id == device.id,
                DeviceIP.ip_address == ip_address,
            )
        )

        now = datetime.utcnow()

        if existing_ip is None:
            existing_ip = DeviceIP(
                device_id=device.id,
                ip_address=ip_address,
                address_family="ipv4",
                is_current=True,
                first_seen=now,
                last_seen=now,
                source=source,
            )

            self.db.add(existing_ip)

        else:
            existing_ip.is_current = True
            existing_ip.last_seen = now

            if source:
                existing_ip.source = source

        # Mark other IPv4 addresses of this device as not current.
        other_ips = self.db.scalars(
            select(DeviceIP).where(
                DeviceIP.device_id == device.id,
                DeviceIP.ip_address != ip_address,
                DeviceIP.address_family == "ipv4",
                DeviceIP.is_current.is_(True),
            )
        ).all()

        for other_ip in other_ips:
            other_ip.is_current = False

        return existing_ip

    # ============================================================
    # Port Synchronization
    # ============================================================

    def _sync_ports(
        self,
        device: Device,
        ports: list[DiscoveredPort],
        source: str | None,
    ) -> None:
        """
        Synchronize discovered TCP/UDP ports.
        """

        now = datetime.utcnow()

        seen_ports: set[tuple[int, str]] = set()

        for port in ports:
            key = (
                port.port_number,
                port.protocol,
            )

            seen_ports.add(key)

            existing_port = self.db.scalar(
                select(DevicePort).where(
                    DevicePort.device_id == device.id,
                    DevicePort.port_number
                    == port.port_number,
                    DevicePort.protocol
                    == port.protocol,
                )
            )

            if existing_port is None:
                existing_port = DevicePort(
                    device_id=device.id,
                    port_number=port.port_number,
                    protocol=port.protocol,
                    state=port.state,
                    service=port.service,
                    product=port.product,
                    version=port.version,
                    first_seen=now,
                    last_seen=now,
                    source=source,
                )

                self.db.add(existing_port)

                self._create_event(
                    device=device,
                    event_type="port_discovered",
                    severity="info",
                    message=(
                        f"{port.protocol.upper()} "
                        f"port {port.port_number} "
                        f"discovered"
                    ),
                    event_data={
                        "port": port.port_number,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service": port.service,
                        "product": port.product,
                        "version": port.version,
                    },
                )

            else:
                previous_state = existing_port.state

                existing_port.state = port.state
                existing_port.service = port.service
                existing_port.product = port.product
                existing_port.version = port.version
                existing_port.last_seen = now

                if source:
                    existing_port.source = source

                if (
                    previous_state != port.state
                    and port.state is not None
                ):
                    self._create_event(
                        device=device,
                        event_type="port_state_changed",
                        severity="info",
                        message=(
                            f"{port.protocol.upper()} "
                            f"port {port.port_number} "
                            f"changed from "
                            f"{previous_state} to "
                            f"{port.state}"
                        ),
                        event_data={
                            "port": port.port_number,
                            "protocol": port.protocol,
                            "previous_state": previous_state,
                            "new_state": port.state,
                        },
                    )

        # --------------------------------------------------------
        # Ports not returned by the latest scan
        #
        # We do NOT delete them.
        # Instead, their last_seen timestamp remains historical.
        # --------------------------------------------------------

    # ============================================================
    # Events
    # ============================================================

    def _create_event(
        self,
        device: Device,
        event_type: str,
        severity: str,
        message: str,
        event_data: dict | None = None,
    ) -> DeviceEvent:
        event = DeviceEvent(
            device_id=device.id,
            event_type=event_type,
            severity=severity,
            message=message,
            event_data=event_data,
        )

        self.db.add(event)

        return event

    # ============================================================
    # Read Helpers
    # ============================================================

    def get_device(
        self,
        device_id: int,
    ) -> Device | None:
        return self.db.get(
            Device,
            device_id,
        )

    def get_devices(
        self,
    ) -> list[Device]:
        return self.db.scalars(
            select(Device).order_by(
                Device.last_seen.desc()
            )
        ).all()

    def get_device_by_ip(
        self,
        ip_address: str,
    ) -> Device | None:
        return self.db.scalar(
            select(Device)
            .join(DeviceIP)
            .where(
                DeviceIP.ip_address
                == ip_address
            )
        )

    def get_device_by_mac(
        self,
        mac_address: str,
    ) -> Device | None:
        return self.db.scalar(
            select(Device).where(
                Device.mac_address
                == mac_address
            )
        )