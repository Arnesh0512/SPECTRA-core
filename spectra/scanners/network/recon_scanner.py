"""
spectra.scanners.network.recon_scanner
===========================================
Integrated low-impact network reconnaissance and observation engine.
Absorbs DNS resolution, target provenance recovery, direct port scanning,
and pure Python SSH host key discovery into the core library flow.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import yaml

from spectra.utils.logger import log_info, log_step


DOMAIN_PATTERN = re.compile(r"(?i)(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?::\d{1,5})?")
HOSTNAME_PATTERN = re.compile(r"(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


class NetworkReconFinding:
    """Represents a network reconnaissance observation."""
    def __init__(self, finding_type: str, evidence_type: str, detected_term: str, category: str, provenance: dict, observation: dict):
        self.finding_type = finding_type
        self.evidence_type = evidence_type
        self.detected_term = detected_term
        self.category = category
        self.provenance = provenance
        self.observation = observation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": "network",
            "finding_type": self.finding_type,
            "evidence_type": self.evidence_type,
            "detected_term": self.detected_term,
            "category": self.category,
            "provenance": self.provenance,
            "observation": self.observation,
            "security_findings": [],
            "quantum_safe": False,
            "shor_vulnerable": True
        }


class NetworkReconScanner:
    """Executes low-impact DNS, port, TLS, and pure Python SSH network reconnaissance."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "network_indicators.yaml"
        self.rules = self._load_rules(rules_file)
        self.default_ports = self.rules.get("default_ports", [22, 443, 8443, 9443])
        self.tls_ports = set(self.rules.get("tls_ports", [443, 8443, 9443]))
        self.ssh_ports = set(self.rules.get("ssh_ports", [22]))

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    @staticmethod
    def is_nmap_available() -> bool:
        """Returns True if nmap binary is discoverable in system PATH."""
        return shutil.which("nmap") is not None

    def normalize_hostname(self, value: str) -> Optional[str]:
        value = value.strip().lower()
        value = re.sub(r"^https?://", "", value).rstrip("/")
        if ":" in value:
            value = value.split(":")[0]
        value = value.rstrip(".")
        if not value or any(char.isspace() for char in value):
            return None
        try:
            socket.inet_pton(socket.AF_INET, value)
            return value
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, value)
                return value
            except OSError:
                pass
        return value if HOSTNAME_PATTERN.fullmatch(value) else None

    def run_nmap_scan(
        self,
        hostname: str,
        ports: Optional[List[int]] = None,
        timeout: float = 30.0,
    ) -> List[Dict[str, Any]]:
        """
        Executes Nmap with light version detection against target hostname.
        Uses -Pn (bypass ping discovery) and --open (filter closed ports) for fast, reliable scanning.
        """
        cmd = ["nmap", "-Pn", "-sV", "--version-light", "-T4", "--open"]
        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in sorted(set(ports)))])
        cmd.extend(["-oX", "-", hostname])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except Exception as e:
            log_info(f"Nmap execution error on {hostname}: {e}")
            return []

        stdout = proc.stdout or ""
        xml_idx = stdout.find("<nmaprun")
        if xml_idx == -1:
            return []

        try:
            root = ET.fromstring(stdout[xml_idx:])
        except ET.ParseError as e:
            log_info(f"Failed to parse Nmap XML output for {hostname}: {e}")
            return []

        discovered: List[Dict[str, Any]] = []
        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            if status_el is not None and status_el.get("state") != "up":
                continue

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                port_id_str = port_el.get("portid")
                if not port_id_str or not port_id_str.isdigit():
                    continue
                port_id = int(port_id_str)
                proto = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                tunnel = service_el.get("tunnel") if service_el is not None else None
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""

                s_lower = service_name.lower()
                is_tls = (
                    tunnel == "ssl"
                    or s_lower in {"https", "imaps", "pop3s", "smtps", "ftps", "ldaps", "openvpn", "ssl", "tls"}
                    or (port_id in self.tls_ports and s_lower not in {"ssh", "telnet"})
                )
                is_ssh = (
                    s_lower == "ssh"
                    or port_id in self.ssh_ports
                )

                discovered.append({
                    "port": port_id,
                    "protocol": proto,
                    "service": service_name,
                    "tunnel": tunnel,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "is_tls": is_tls,
                    "is_ssh": is_ssh,
                    "observation_source": "nmap",
                })

        return discovered

    def discover_services(
        self,
        hostname: str,
        ports: Optional[List[int]] = None,
        timeout: float = 30.0,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Discovers open ports and underlying services using a hybrid approach:
        - If Nmap is installed, runs rapid service detection (-sV --version-light).
        - If Nmap is absent or fails, falls back completely to native socket probing.
        Returns (list_of_services, engine_name).
        """
        if self.is_nmap_available():
            try:
                services = self.run_nmap_scan(hostname, ports=ports, timeout=timeout)
                return services, "nmap"
            except Exception as exc:
                log_info(f"Nmap scan encountered an issue ({exc}). Falling back to native socket probe.")

        # Complete fallback to native method: blind socket search
        candidate_ports = ports or self.default_ports
        open_ports = self.direct_ports(hostname, candidate_ports, timeout=min(timeout, 5.0))
        services = []
        for ep in open_ports:
            p = ep["port"]
            is_ssh = p in self.ssh_ports
            is_tls = p in self.tls_ports
            s_name = "ssh" if is_ssh else ("https" if is_tls else "unknown")
            services.append({
                "port": p,
                "protocol": "tcp",
                "service": s_name,
                "tunnel": "ssl" if is_tls else None,
                "product": "",
                "version": "",
                "extrainfo": "",
                "is_tls": is_tls,
                "is_ssh": is_ssh,
                "observation_source": "socket_connect",
            })
        return services, "native"

    def explicit_targets(self, values: List[str]) -> List[Dict[str, Any]]:
        result = []
        for value in values:
            hostname = self.normalize_hostname(value)
            if hostname:
                result.append({"hostname": hostname, "sources": [{"source": "enterprise_input"}]})
        return result

    def dns_lookup(self, hostname: str) -> Dict[str, Any]:
        addresses: Dict[str, set] = {"A": set(), "AAAA": set()}
        try:
            for family, _, _, _, endpoint in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
                if family == socket.AF_INET:
                    addresses["A"].add(endpoint[0])
                elif family == socket.AF_INET6:
                    addresses["AAAA"].add(endpoint[0])
        except socket.gaierror as error:
            return {"hostname": hostname, "records": {"A": [], "AAAA": [], "CNAME": []}, "error": str(error), "observation_source": "socket.getaddrinfo"}
        cname: List[str] = []
        source = "socket.getaddrinfo"
        try:
            import dns.resolver  # type: ignore[import-not-found]
            cname = sorted(str(item.target).rstrip(".") for item in dns.resolver.resolve(hostname, "CNAME"))
            source = "socket.getaddrinfo+dnspython"
        except Exception:
            pass
        return {"hostname": hostname, "records": {"A": sorted(addresses["A"]), "AAAA": sorted(addresses["AAAA"]), "CNAME": cname}, "observation_source": source}

    def direct_ports(self, hostname: str, ports: List[int], timeout: float) -> List[Dict[str, Any]]:
        result = []
        for port in ports:
            try:
                with socket.create_connection((hostname, port), timeout=timeout):
                    result.append({"port": port, "transport": "tcp", "service_hint": None, "observation_source": "socket_connect"})
            except OSError:
                continue
        return result

    def ssh_keyscan(self, hostname: str, port: int, timeout: int) -> List[Dict[str, Any]]:
        """Cross-platform, pure Python SSH host key retrieval using Paramiko with socket fallback."""
        result = []
        try:
            import paramiko
            sock = socket.create_connection((hostname, port), timeout=timeout)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=timeout)
            server_key = transport.get_remote_server_key()
            transport.close()
            try:
                sock.close()
            except Exception:
                pass

            if server_key:
                key_algo = server_key.get_name()
                key_bytes = server_key.asbytes()
                fingerprint = base64.b64encode(hashlib.sha256(key_bytes).digest()).decode().rstrip("=")
                result.append({
                    "host_key_algorithm": key_algo,
                    "host_key_sha256": f"SHA256:{fingerprint}",
                    "observation_source": "paramiko_pure_python"
                })
        except ImportError:
            try:
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner.startswith("SSH-"):
                        result.append({
                            "host_key_algorithm": "SSH-Server-Banner",
                            "host_key_sha256": banner,
                            "observation_source": "socket_banner_grab"
                        })
            except Exception:
                pass
        except Exception:
            pass
        return result

    def scan_targets(self, targets: List[Dict[str, Any]], ports: Optional[List[int]] = None, timeout: float = 5.0) -> List[NetworkReconFinding]:
        ports = ports or self.default_ports
        findings: List[NetworkReconFinding] = []

        for target in targets:
            hostname, sources = target["hostname"], target["sources"]
            dns = self.dns_lookup(hostname)
            addresses = [*dns["records"].get("A", []), *dns["records"].get("AAAA", [])]

            for ip in addresses:
                findings.append(NetworkReconFinding(
                    finding_type="network_crypto_observation",
                    evidence_type="dns_resolution",
                    detected_term=ip,
                    category="network_endpoint",
                    provenance={"hostname": hostname, "resolved_ip": ip, "port": None, "protocol": "DNS", "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "target_sources": sources},
                    observation=dns
                ))

            open_ports = self.direct_ports(hostname, ports, timeout)
            for endpoint in open_ports:
                port = endpoint["port"]
                findings.append(NetworkReconFinding(
                    finding_type="network_crypto_observation",
                    evidence_type="open_tcp_port",
                    detected_term=str(port),
                    category="network_service_candidate",
                    provenance={"hostname": hostname, "resolved_ip": addresses[0] if addresses else None, "port": port, "protocol": "TCP", "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "target_sources": sources},
                    observation=endpoint
                ))

                if port in self.ssh_ports:
                    for obs in self.ssh_keyscan(hostname, port, int(timeout)):
                        findings.append(NetworkReconFinding(
                            finding_type="network_crypto_observation",
                            evidence_type="ssh_host_key",
                            detected_term=obs["host_key_algorithm"],
                            category="host_key",
                            provenance={"hostname": hostname, "resolved_ip": addresses[0] if addresses else None, "port": port, "protocol": "SSH", "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "target_sources": sources},
                            observation=obs
                        ))

        return findings