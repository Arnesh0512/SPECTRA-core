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
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
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
    """Executes low-impact DNS, port, TLS, and pure Python SSH network reconnaissance[cite: 29]."""

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

    def normalize_hostname(self, value: str) -> Optional[str]:
        value = value.strip().lower().rstrip(".")
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