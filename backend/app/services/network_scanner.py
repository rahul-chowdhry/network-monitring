from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import psutil

from ..config import settings


class NetworkScannerError(Exception):
    """Raised when a network scan cannot be completed."""


@dataclass
class DiscoveredPort:
    port_number: int
    protocol: str = "tcp"
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class DiscoveredHost:
    ip_address:str 
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    hostname_source: Optional[str] = None
    vendor: Optional[str] = None
    vendor_source: Optional[str] = None
    discovery_source: Optional[str] = None
    discovery_confidence: Optional[float] = None
    is_estimated: bool = False
    status: str = "online"
    latency_ms: Optional[float] = None
    ports: list[DiscoveredPort] = field(default_factory=list)

class NetworkScanner:
    """
    Local network discovery and lightweight port/service scanner.

    Intended only for networks the user owns
    or is authorized to administer.
    """

    def __init__(
        self,
        nmap_path: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self.nmap_path = nmap_path or settings.nmap_path
        self.default_timeout = (
            timeout or settings.default_scan_timeout_seconds
        )

    def check_nmap(self) -> bool:
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            return result.returncode == 0

        except (
            FileNotFoundError,
            subprocess.TimeoutExpired,
            OSError,
        ):
            return False

    def get_nmap_version(self) -> Optional[str]:
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return None

            lines = result.stdout.strip().splitlines()

            if not lines:
                return None

            return lines[0].strip()

        except (
            FileNotFoundError,
            subprocess.TimeoutExpired,
            OSError,
        ):
            return None

    @staticmethod
    def _is_valid_local_ipv4(address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False

        if ip.version != 4:
            return False

        if ip.is_loopback:
            return False

        if ip.is_link_local:
            return False

        return True

    def get_local_subnets(self) -> list[str]:
        subnets: list[str] = []

        interfaces = psutil.net_if_addrs()

        for _, addresses in interfaces.items():
            for address in addresses:
                if address.family != socket.AF_INET:
                    continue

                ip_address = address.address
                netmask = address.netmask

                if not netmask:
                    continue

                if not self._is_valid_local_ipv4(ip_address):
                    continue

                try:
                    network = ipaddress.ip_network(
                        f"{ip_address}/{netmask}",
                        strict=False,
                    )

                    network_string = str(network)

                    if network_string not in subnets:
                        subnets.append(network_string)

                except ValueError:
                    continue

        private_subnets: list[str] = []

        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet)

                if network.is_private:
                    private_subnets.append(subnet)

            except ValueError:
                continue

        if private_subnets:
            return private_subnets

        return subnets

    def get_primary_subnet(self) -> Optional[str]:
        subnets = self.get_local_subnets()

        if not subnets:
            return None

        preferred_ranges = (
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
        )

        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet)

                for preferred in preferred_ranges:
                    if network.subnet_of(preferred):
                        return subnet

            except ValueError:
                continue

        return subnets[0]

    def get_local_ipv4_addresses(self) -> list[str]:
        addresses: list[str] = []

        for _, interface_addresses in psutil.net_if_addrs().items():
            for address in interface_addresses:
                if address.family != socket.AF_INET:
                    continue

                ip_address = address.address

                if not self._is_valid_local_ipv4(ip_address):
                    continue

                if ip_address not in addresses:
                    addresses.append(ip_address)

        return addresses

    def _run_nmap(
        self,
        subnet: str,
        arguments: list[str],
    ) -> str:

        if not self.check_nmap():
            raise NetworkScannerError(
                f"Nmap executable not available: {self.nmap_path}"
            )

        command = [
            self.nmap_path,
            *arguments,
            "-oX",
            "-",
            subnet,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.default_timeout,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise NetworkScannerError(
                f"Nmap scan timed out after "
                f"{self.default_timeout} seconds."
            ) from exc

        except FileNotFoundError as exc:
            raise NetworkScannerError(
                f"Nmap executable not found: {self.nmap_path}"
            ) from exc

        except OSError as exc:
            raise NetworkScannerError(
                f"Could not start Nmap: {exc}"
            ) from exc

        if result.returncode != 0:
            error_message = (
                result.stderr.strip()
                or result.stdout.strip()
                or f"Nmap exited with code {result.returncode}"
            )

            raise NetworkScannerError(
                f"Nmap scan failed: {error_message}"
            )

        if not result.stdout.strip():
            raise NetworkScannerError(
                "Nmap returned empty XML output."
            )

        return result.stdout

    @staticmethod
    def _normalize_mac(
        mac: Optional[str],
    ) -> Optional[str]:

        if not mac:
            return None

        cleaned = re.sub(
            r"[^0-9A-Fa-f]",
            "",
            mac,
        )

        if len(cleaned) != 12:
            return mac.upper()

        return ":".join(
            cleaned[index:index + 2]
            for index in range(0, 12, 2)
        ).upper()

    @staticmethod
    def _get_host_ipv4(
        host_element: ET.Element,
    ) -> Optional[str]:

        for address in host_element.findall("address"):
            if address.get("addrtype") == "ipv4":
                return address.get("addr")

        return None

    @staticmethod
    def _get_host_mac(
        host_element: ET.Element,
    ) -> tuple[Optional[str], Optional[str]]:

        for address in host_element.findall("address"):
            if address.get("addrtype") == "mac":
                return (
                    address.get("addr"),
                    address.get("vendor"),
                )

        return None, None

    @staticmethod
    def _get_hostname(
        host_element: ET.Element,
    ) -> Optional[str]:

        hostnames = host_element.find("hostnames")

        if hostnames is None:
            return None

        for hostname in hostnames.findall("hostname"):
            name = hostname.get("name")

            if name:
                return name

        return None

    def _parse_hosts(
        self,
        xml_output: str,
    ) -> list[DiscoveredHost]:

        try:
            root = ET.fromstring(xml_output)

        except ET.ParseError as exc:
            raise NetworkScannerError(
                f"Could not parse Nmap XML output: {exc}"
            ) from exc

        discovered: list[DiscoveredHost] = []

        for host_element in root.findall("host"):

            status_element = host_element.find("status")

            state = "online"

            if status_element is not None:
                state = status_element.get(
                    "state",
                    "online",
                )

            if state != "up":
                continue

            ip_address = self._get_host_ipv4(
                host_element
            )

            if not ip_address:
                continue

            mac_address, vendor = self._get_host_mac(
                host_element
            )

            hostname = self._get_hostname(
                host_element
            )

            latency_ms = None

            times = host_element.find("times")

            if times is not None:
                raw_rtt = times.get("srtt")

                if raw_rtt:
                    try:
                        latency_ms = (
                            float(raw_rtt) / 1000.0
                        )

                    except ValueError:
                        latency_ms = None

            ports: list[DiscoveredPort] = []

            ports_element = host_element.find("ports")

            if ports_element is not None:

                for port_element in ports_element.findall(
                    "port"
                ):

                    protocol = (
                        port_element.get(
                            "protocol",
                            "tcp",
                        )
                        or "tcp"
                    )

                    raw_port = port_element.get(
                        "portid"
                    )

                    if not raw_port:
                        continue

                    try:
                        port_number = int(raw_port)

                    except ValueError:
                        continue

                    state_element = port_element.find(
                        "state"
                    )

                    port_state = None

                    if state_element is not None:
                        port_state = state_element.get(
                            "state"
                        )

                    service_element = port_element.find(
                        "service"
                    )

                    service = None
                    product = None
                    version = None

                    if service_element is not None:

                        service = service_element.get(
                            "name"
                        )

                        product = service_element.get(
                            "product"
                        )

                        version = service_element.get(
                            "version"
                        )

                    ports.append(
                        DiscoveredPort(
                            port_number=port_number,
                            protocol=protocol,
                            state=port_state,
                            service=service,
                            product=product,
                            version=version,
                        )
                    )

            vendor_source = (
                "nmap"
                if vendor
                else None
            )

            discovered.append(
                DiscoveredHost(
                    ip_address=ip_address,
                    mac_address=self._normalize_mac(
                        mac_address
                    ),
                    hostname=hostname,
                    hostname_source="nmap" if hostname else None,
                    vendor=vendor,
                    vendor_source=vendor_source,
                    discovery_source="nmap",
                    discovery_confidence=0.95,
                    is_estimated=False,
                    status="online",
                    latency_ms=latency_ms,
                    ports=ports,
                )
            )

        return discovered

    def enrich_hostnames(
        self,
        hosts: list[DiscoveredHost],
    ) -> list[DiscoveredHost]:

        for host in hosts:

            if host.hostname:
                continue

            try:
                resolved_name, _, _ = socket.gethostbyaddr(
                    host.ip_address
                )

                if resolved_name:
                    host.hostname = resolved_name
                    host.hostname_source = "reverse_dns"

            except (
                socket.herror,
                socket.gaierror,
                OSError,
            ):
                pass

        return hosts

    def discover_hosts(
        self,
        subnet: Optional[str] = None,
    ) -> list[DiscoveredHost]:

        target_subnet = (
            subnet
            or self.get_primary_subnet()
        )

        if not target_subnet:
            raise NetworkScannerError(
                "Could not automatically determine "
                "a local IPv4 subnet."
            )

        xml_output = self._run_nmap(
            target_subnet,
            [
                "-sn",
                "-PR",
                "-PE",
                "-PS80,443",
                "-T3",
            ],
        )

        hosts = self._parse_hosts(
            xml_output
        )

        return self.enrich_hostnames(
            hosts
        )

    def scan_host_ports(
        self,
        ip_address: str,
    ) -> DiscoveredHost:

        try:
            ipaddress.ip_address(
                ip_address
            )

        except ValueError as exc:
            raise NetworkScannerError(
                f"Invalid IPv4 address: {ip_address}"
            ) from exc

        original_timeout = (
            self.default_timeout
        )

        try:

            self.default_timeout = max(
                original_timeout,
                30,
            )

            xml_output = self._run_nmap(
                ip_address,
                [
                    "-Pn",
                    "-sT",
                    "-sV",
                    "--version-light",
                    "--top-ports",
                    "100",
                    "-T3",
                ],
            )

        finally:

            self.default_timeout = (
                original_timeout
            )

        hosts = self._parse_hosts(
            xml_output
        )

        if not hosts:

            return DiscoveredHost(
                ip_address=ip_address,
                status="offline",
                discovery_source="nmap",
            )

        hosts = self.enrich_hostnames(
            hosts
        )

        return hosts[0]

    def scan_hosts_with_ports(
        self,
        subnet: Optional[str] = None,
    ) -> list[DiscoveredHost]:

        target_subnet = (
            subnet
            or self.get_primary_subnet()
        )

        if not target_subnet:
            raise NetworkScannerError(
                "Could not automatically determine "
                "a local IPv4 subnet."
            )

        xml_output = self._run_nmap(
            target_subnet,
            [
                "-sT",
                "-sV",
                "--version-light",
                "--top-ports",
                "50",
                "-T4",
                "--host-timeout",
                "10s",
            ],
        )

        hosts = self._parse_hosts(
            xml_output
        )

        return self.enrich_hostnames(
            hosts
        )

    def scan(
        self,
        subnet: Optional[str] = None,
        include_ports: bool = True,
    ) -> list[DiscoveredHost]:

        if include_ports:
            return self.scan_hosts_with_ports(
                subnet
            )

        return self.discover_hosts(
            subnet
        )


def discover_network_hosts(
    subnet: Optional[str] = None,
) -> list[DiscoveredHost]:

    scanner = NetworkScanner()

    return scanner.discover_hosts(
        subnet
    )


def scan_network_ports(
    subnet: Optional[str] = None,
) -> list[DiscoveredHost]:

    scanner = NetworkScanner()

    return scanner.scan_hosts_with_ports(
        subnet
    )


def scan_single_host(
    ip_address: str,
) -> DiscoveredHost:

    scanner = NetworkScanner()

    return scanner.scan_host_ports(
        ip_address
    )

