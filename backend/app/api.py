from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .auth import authenticate_user, create_access_token, get_current_user
from .database import get_db
from .models import AdminUser, DeviceEvent, ScanRun
from .schemas import TokenResponse
from .services.device_service import DeviceService
from .services.network_scanner import NetworkScanner


router = APIRouter(prefix="/api")


@router.post("/auth/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(
        db,
        form_data.username,
        form_data.password,
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is inactive",
        )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
        },
    }


@router.get("/devices")
def get_devices(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    service = DeviceService(db)

    devices = service.get_devices()

    return {
        "count": len(devices),
        "devices": [
            {
                "id": device.id,
                "mac_address": device.mac_address,
                "hostname": device.hostname,
                "vendor": device.vendor,
                "status": device.status,
                "latency_ms": (
                    float(device.latency_ms)
                    if device.latency_ms is not None
                    else None
                ),
                "discovery_source": device.discovery_source,
                "discovery_confidence": (
                    float(device.discovery_confidence)
                    if device.discovery_confidence is not None
                    else None
                ),
                "is_estimated": device.is_estimated,
                "first_seen": device.first_seen,
                "last_seen": device.last_seen,
                "ips": [
                    {
                        "id": ip.id,
                        "ip_address": ip.ip_address,
                        "address_family": ip.address_family,
                        "is_current": ip.is_current,
                        "source": ip.source,
                    }
                    for ip in device.ips
                ],
                "ports": [
                    {
                        "id": port.id,
                        "port_number": port.port_number,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service": port.service,
                        "product": port.product,
                        "version": port.version,
                    }
                    for port in device.ports
                ],
            }
            for device in devices
        ],
    }


@router.get("/devices/{device_id}")
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    service = DeviceService(db)

    device = service.get_device(device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    return {
        "id": device.id,
        "mac_address": device.mac_address,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "status": device.status,
        "latency_ms": (
            float(device.latency_ms)
            if device.latency_ms is not None
            else None
        ),
        "discovery_source": device.discovery_source,
        "discovery_confidence": (
            float(device.discovery_confidence)
            if device.discovery_confidence is not None
            else None
        ),
        "is_estimated": device.is_estimated,
        "first_seen": device.first_seen,
        "last_seen": device.last_seen,
        "ips": [
            {
                "id": ip.id,
                "ip_address": ip.ip_address,
                "address_family": ip.address_family,
                "is_current": ip.is_current,
                "source": ip.source,
            }
            for ip in device.ips
        ],
        "ports": [
            {
                "id": port.id,
                "port_number": port.port_number,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "product": port.product,
                "version": port.version,
            }
            for port in device.ports
        ],
    }


@router.get("/events")
def get_events(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    events = (
        db.query(DeviceEvent)
        .order_by(DeviceEvent.created_at.desc())
        .limit(50)
        .all()
    )

    return {
        "count": len(events),
        "events": [
            {
                "id": event.id,
                "device_id": event.device_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "message": event.message,
                "created_at": event.created_at,
            }
            for event in events
        ],
    }


@router.post("/scan")
def scan_network(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user),
):
    scanner = NetworkScanner()
    service = DeviceService(db)

    started_at = datetime.utcnow()

    scan_run = ScanRun(
        status="running",
        started_at=started_at,
        subnet=scanner.get_primary_subnet(),
        devices_found=0,
    )

    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    scan_id = scan_run.id

    try:
        hosts = scanner.scan_hosts_with_ports()

        devices = service.sync_hosts(hosts)

        scan_run = db.get(ScanRun, scan_id)

        if scan_run is None:
            raise RuntimeError("Scan run could not be reloaded")

        scan_run.status = "completed"
        scan_run.completed_at = datetime.utcnow()
        scan_run.devices_found = len(devices)

        db.commit()

        return {
            "status": "completed",
            "scan_id": scan_id,
            "hosts_discovered": len(hosts),
            "devices_synced": len(devices),
        }

    except Exception as exc:
        db.rollback()

        failed_scan = db.get(ScanRun, scan_id)

        if failed_scan is not None:
            failed_scan.status = "failed"
            failed_scan.completed_at = datetime.utcnow()
            failed_scan.error_message = str(exc)
            db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Network scan failed: {exc}",
        ) from exc