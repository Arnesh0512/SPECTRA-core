"""
spectra.scanners.network.protocol_scanner
==============================================
Network protocol cryptographic property scanner.
Audits cryptographic posture of protocols such as SSH (daemon, client, user configs),
IPsec, and plain-text protocols, inspecting key exchange algorithms, ciphers, and MAC algorithms.
Loaded via rules/network_indicators.yaml and supports system-wide and container mounts.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set
import yaml


@dataclass
class ProtocolFinding:
    """Represents cryptographic posture of a network protocol or service config."""
    source_domain: str = "network"
    protocol: str = "ssh"  # ssh, ipsec, plaintext
    file_path: str = ""
    line_number: int = 1
    service_target: str = ""
    kex_algorithms: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    host_key_algorithms: List[str] = field(default_factory=list)
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "protocol": self.protocol,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "service_target": self.service_target,
            "kex_algorithms": self.kex_algorithms,
            "ciphers": self.ciphers,
            "macs": self.macs,
            "host_key_algorithms": self.host_key_algorithms,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


# Directives commonly found in sshd_config or ssh_config
SSH_DIRECTIVE_REGEX = re.compile(
    r"^\s*(?P<key>KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|PubkeyAcceptedKeyTypes|PubkeyAcceptedAlgorithms|CASignatureAlgorithms|IdentityFile|Port|Host|Match)\s+(?P<val>[^\n#]+)",
    re.MULTILINE | re.IGNORECASE
)

# Directives in ipsec.conf / strongswan.conf
IPSEC_DIRECTIVE_REGEX = re.compile(
    r"^\s*(?P<key>ike|esp|ah|keyexchange)\s*=\s*(?P<val>[^\n#]+)",
    re.MULTILINE | re.IGNORECASE
)


class ProtocolScanner:
    """Scans protocol configuration files (e.g., sshd_config, ~/.ssh/config, ipsec.conf) for cryptographic compliance."""

    CONFIG_NAMES = {"sshd_config", "ssh_config", "ipsec.conf", "strongswan.conf"}

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "network_indicators.yaml"
        self.rules = self._load_rules(rules_file)
        self.weak_kex = self.rules.get("weak_ssh_kex", ["group1-sha1", "group14-sha1"])
        self.weak_ciphers = self.rules.get("weak_ssh_ciphers", ["3des", "arcfour", "blowfish", "cast128"])
        self.weak_macs = self.rules.get("weak_ssh_macs", ["md5", "sha1"])
        self.weak_ipsec_ciphers = self.rules.get("weak_ipsec_ciphers", ["3des", "des", "blowfish", "null"])
        self.weak_ipsec_kex = self.rules.get("weak_ipsec_kex", ["modp768", "modp1024", "modp1536", "dh1", "dh2", "dh5"])
        self.weak_ipsec_hashes = self.rules.get("weak_ipsec_hashes", ["md5", "sha1"])

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _get_system_fallback_paths(self, target_dir: Optional[Path] = None) -> List[Path]:
        """Returns OS-agnostic common default SSH and IPsec configuration directories across mounts."""
        from spectra.utils.system_paths import get_protocol_config_paths
        return get_protocol_config_paths(target_dir)

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
        config_discovered_ssh_paths: Optional[Dict[str, str]] = None,
    ) -> List[ProtocolFinding]:
        findings: List[ProtocolFinding] = []
        excluded = set(excluded_dirs or [])

        # 1. Gather all candidate search directories across target_dir and system root mounts
        search_directories: List[Path] = [target_dir] if target_dir and target_dir.exists() else []
        for path in self._get_system_fallback_paths(target_dir):
            if path not in search_directories:
                search_directories.append(path)

        candidate_files: List[Path] = []
        seen_resolved: Set[str] = set()

        def _add_file(f_path: Path):
            try:
                if f_path.is_file():
                    key = str(f_path if "/proc/" in str(f_path) else f_path.resolve())
                    if key not in seen_resolved:
                        seen_resolved.add(key)
                        candidate_files.append(f_path)
            except Exception:
                pass

        # 2. Add files harvested by Infrastructure domain (Dockerfiles, Kubernetes, Compose)
        if config_discovered_ssh_paths:
            for p_str in config_discovered_ssh_paths.keys():
                _add_file(Path(p_str))

        # 3. Walk directories to discover SSH and IPsec configuration files
        for directory in search_directories:
            if not directory.exists():
                continue
            try:
                for root, dirs, files in os.walk(str(directory)):
                    dirs[:] = [
                        d for d in dirs
                        if d not in excluded and not any(part in excluded for part in Path(root, d).parts)
                    ]
                    parent_name = Path(root).name.lower()
                    for f in files:
                        f_lower = f.lower()
                        # Match 1: Standard filenames (sshd_config, ssh_config, ipsec.conf, strongswan.conf)
                        if f_lower in self.CONFIG_NAMES:
                            _add_file(Path(root) / f)
                        # Match 2: User .ssh/config or ssh/config
                        elif f_lower == "config" and parent_name in [".ssh", "ssh"]:
                            _add_file(Path(root) / f)
                        # Match 3: Modular drop-ins (sshd_config.d/*.conf, ssh_config.d/*.conf, ipsec.d/*.conf)
                        elif f_lower.endswith(".conf") and parent_name in [
                            "sshd_config.d", "ssh_config.d", "ipsec.d", "strongswan.d"
                        ]:
                            _add_file(Path(root) / f)
            except Exception:
                pass

        total_files = len(candidate_files)
        for idx, path in enumerate(candidate_files, start=1):
            finding = self.scan_file(path)
            proto_type = "ssh"
            if finding:
                proto_type = finding.protocol
            elif "ipsec" in path.name.lower() or "strongswan" in path.name.lower():
                proto_type = "ipsec"
            elif "ssh" in path.name.lower() or ".ssh" in str(path) or path.name.lower() == "config":
                proto_type = "ssh"
            else:
                proto_type = "protocol"

            if progress_callback and total_files > 0:
                pct = 52.0 + (idx / total_files) * 8.0
                desc = f"Domain 3/4: Auditing [{proto_type.upper()}] ({idx}/{total_files}) {path.name}"
                from spectra.utils.system_paths import format_display_path
                rel_loc = format_display_path(path, target_dir)
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_files}",
                        "type": proto_type,
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )

            if finding:
                # Attach infrastructure source tag if available
                if config_discovered_ssh_paths:
                    key = str(path if "/proc/" in str(path) else path.resolve())
                    src = config_discovered_ssh_paths.get(key) or config_discovered_ssh_paths.get(str(path))
                    if src:
                        finding.raw_metadata["config_source"] = src

                findings.append(finding)

        return findings

    def scan_file(self, file_path: Path) -> Optional[ProtocolFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return None

        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # Check for SSH config
        if "ssh" in name_lower or parent_lower in [".ssh", "ssh", "sshd_config.d", "ssh_config.d"] or name_lower == "config":
            return self._parse_ssh_config(file_path, content)

        # Check for IPsec config
        if "ipsec" in name_lower or "strongswan" in name_lower or parent_lower in ["ipsec.d", "strongswan.d"]:
            return self._parse_ipsec_config(file_path, content)

        return None

    def _parse_ssh_config(self, file_path: Path, content: str) -> Optional[ProtocolFinding]:
        kex_list: List[str] = []
        ciphers_list: List[str] = []
        macs_list: List[str] = []
        hostkeys_list: List[str] = []
        identity_files: List[str] = []
        has_ssh_directives = False
        sec_findings = []

        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        is_server = "sshd" in name_lower or parent_lower == "sshd_config.d"
        is_user = name_lower == "config" and parent_lower in [".ssh", "ssh"]
        service_target = "sshd" if is_server else ("ssh-client-user" if is_user else "ssh-client")
        config_type = "sshd_config" if is_server else ("user_ssh_config" if is_user else "ssh_config")

        for match in SSH_DIRECTIVE_REGEX.finditer(content):
            has_ssh_directives = True
            key = match.group("key").lower()
            val = [x.strip() for x in match.group("val").split(",") if x.strip()]

            if key == "kexalgorithms":
                kex_list.extend(val)
            elif key == "ciphers":
                ciphers_list.extend(val)
            elif key == "macs":
                macs_list.extend(val)
            elif key in ["hostkeyalgorithms", "pubkeyacceptedkeytypes", "pubkeyacceptedalgorithms"]:
                hostkeys_list.extend(val)
            elif key == "identityfile":
                identity_files.extend(val)

        # If no explicit directives matched and filename isn't strictly an SSH config, skip
        if not has_ssh_directives and name_lower not in ["sshd_config", "ssh_config"] and not is_user:
            return None

        # Fallback to OpenSSH defaults if cipher/kex directives were omitted
        if not kex_list:
            kex_list = ["OpenSSH-Default-KEX"]
        if not ciphers_list:
            ciphers_list = ["OpenSSH-Default-Ciphers"]
        if not macs_list:
            macs_list = ["OpenSSH-Default-MACs"]

        # Audit weak SSH KEX (e.g. diffie-hellman-group1-sha1)
        for kex in kex_list:
            if any(wk in kex.lower() for wk in self.weak_kex):
                sec_findings.append({
                    "issue": f"Legacy SHA1-based SSH KexAlgorithm configured: {kex}",
                    "severity": "HIGH"
                })

        # Audit weak SSH ciphers (e.g. 3des-cbc, arcfour)
        for cipher in ciphers_list:
            if any(wc in cipher.lower() for wc in self.weak_ciphers):
                sec_findings.append({
                    "issue": f"Deprecated SSH cipher configured: {cipher}",
                    "severity": "CRITICAL"
                })
            elif "cbc" in cipher.lower():
                sec_findings.append({
                    "issue": f"CBC-mode cipher in SSH configuration: {cipher}",
                    "severity": "MEDIUM"
                })

        # Audit weak SSH MACs (e.g. hmac-md5, hmac-sha1)
        for mac in macs_list:
            if any(wm in mac.lower() for wm in self.weak_macs):
                sec_findings.append({
                    "issue": f"Weak SSH MAC algorithm configured: {mac}",
                    "severity": "HIGH"
                })

        # Check for Post-Quantum SSH Key Exchange
        # OpenSSH 9.0+ defaults to sntrup761x25519-sha512@openssh.com or hybrid ML-KEM
        quantum_safe = any(
            "sntrup761" in k.lower() or "mlkem" in k.lower() or "ml-kem" in k.lower() or "kyber" in k.lower()
            for k in kex_list
        )
        shor_vuln = not quantum_safe

        meta: Dict[str, Any] = {
            "config_type": config_type,
            "service_target": service_target,
        }
        if identity_files:
            meta["referenced_identity_files"] = identity_files

        return ProtocolFinding(
            source_domain="network",
            protocol="ssh",
            file_path=str(file_path.resolve()),
            line_number=1,
            service_target=service_target,
            kex_algorithms=kex_list,
            ciphers=ciphers_list,
            macs=macs_list,
            host_key_algorithms=hostkeys_list,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata=meta,
        )

    def _parse_ipsec_config(self, file_path: Path, content: str) -> Optional[ProtocolFinding]:
        ike_list: List[str] = []
        esp_list: List[str] = []
        sec_findings = []
        has_ipsec_directives = False

        for match in IPSEC_DIRECTIVE_REGEX.finditer(content):
            has_ipsec_directives = True
            key = match.group("key").lower()
            val = match.group("val").strip()
            if key == "ike":
                ike_list.append(val)
            elif key in ["esp", "ah"]:
                esp_list.append(val)

        if not has_ipsec_directives and "ipsec" not in file_path.name.lower():
            return None

        if not ike_list:
            ike_list = ["IPsec-Default-IKE"]
        if not esp_list:
            esp_list = ["IPsec-Default-ESP"]

        # Audit weak IPsec ciphers and parameters
        for entry in ike_list + esp_list:
            entry_lower = entry.lower()
            for wc in self.weak_ipsec_ciphers:
                if wc in entry_lower:
                    sec_findings.append({
                        "issue": f"Weak cipher configured in IPsec tunnel: {wc}",
                        "severity": "CRITICAL"
                    })
            for wk in self.weak_ipsec_kex:
                if wk in entry_lower:
                    sec_findings.append({
                        "issue": f"Deprecated Diffie-Hellman group in IPsec: {wk}",
                        "severity": "HIGH"
                    })
            for wh in self.weak_ipsec_hashes:
                if wh in entry_lower:
                    sec_findings.append({
                        "issue": f"Deprecated hash function in IPsec: {wh}",
                        "severity": "HIGH"
                    })

        return ProtocolFinding(
            source_domain="network",
            protocol="ipsec",
            file_path=str(file_path.resolve()),
            line_number=1,
            service_target="ipsec-vpn",
            kex_algorithms=ike_list,
            ciphers=esp_list,
            macs=[],
            host_key_algorithms=[],
            quantum_safe=False,
            shor_vulnerable=True,
            security_findings=sec_findings,
            raw_metadata={"config_type": "ipsec_config"}
        )