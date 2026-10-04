"""
spectra.scanners.network.nginx_scanner
===========================================
Static configuration scanner for Nginx and Apache web servers.
Parses configuration directives for TLS protocols, cipher suites,
curve preferences, and referenced certificate file paths.
Loaded via rules/network_indicators.yaml.
"""

from dataclasses import dataclass, field
import platform
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional
import yaml


@dataclass
class NginxFinding:
    """Represents cryptographic posture extracted from a web server configuration."""
    source_domain: str = "network"
    config_type: str = "nginx"
    file_path: str = ""
    line_number: int = 0
    server_name: str = "default"
    listen_port: str = "443"
    protocols: List[str] = field(default_factory=list)
    ciphers: str = ""
    ecdh_curve: str = ""
    certificate_path: Optional[str] = None
    certificate_key_path: Optional[str] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "config_type": self.config_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "server_name": self.server_name,
            "listen_port": self.listen_port,
            "protocols": self.protocols,
            "ciphers": self.ciphers,
            "ecdh_curve": self.ecdh_curve,
            "certificate_path": self.certificate_path,
            "certificate_key_path": self.certificate_key_path,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


# Regex to match directives in Nginx blocks
DIRECTIVE_REGEX = re.compile(
    r"^\s*(?P<key>ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|"
    r"ssl_certificate|ssl_certificate_key|ssl_ecdh_curve|server_name|listen)\s+(?P<val>[^;]+);",
    re.MULTILINE
)

SERVER_BLOCK_REGEX = re.compile(r"server\s*\{", re.MULTILINE)


class NginxScanner:
    """Discovers and evaluates cryptographic settings across Nginx/Apache configuration files using rules/network_indicators.yaml."""

    CONFIG_EXTENSIONS = {".conf", ".nginx", ".vhost"}

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "network_indicators.yaml"
        self.rules = self._load_rules(rules_file)
        self.insecure_tls_versions = set(self.rules.get("insecure_tls_versions", ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]))
        self.insecure_cipher_tokens = self.rules.get("insecure_cipher_tokens", ["MD5", "RC4", "DES", "3DES", "NULL", "EXPORT"])

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _get_system_fallback_paths(self, target_dir: Optional[Path] = None) -> List[Path]:
        """Returns OS-agnostic common default web server configuration directories across mounts."""
        from spectra.utils.system_paths import get_webserver_config_paths
        return get_webserver_config_paths(target_dir)

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[NginxFinding]:
        findings: List[NginxFinding] = []
        excluded = set(excluded_dirs or [])

        # Gather target directory and discovered root/mounted web server configuration paths
        search_directories = [target_dir] if target_dir and target_dir.exists() else []
        for path in self._get_system_fallback_paths(target_dir):
            if path not in search_directories:
                search_directories.append(path)

        config_files: List[Path] = []
        for directory in search_directories:
            if not directory.exists():
                continue
            for path in directory.rglob("*"):
                if not path.is_file():
                    continue
                if any(part in excluded for part in path.parts):
                    continue
                if path.suffix.lower() in self.CONFIG_EXTENSIONS or path.name in ["nginx.conf", "httpd.conf"]:
                    config_files.append(path)

        total_cfg = len(config_files)
        for idx, path in enumerate(config_files, start=1):
            if progress_callback and total_cfg > 0:
                pct = 90.0 + (idx / total_cfg) * 4.0
                desc = f"Domain 4/4: Auditing Nginx ({idx}/{total_cfg}) {path.name}"
                from spectra.utils.system_paths import format_display_path
                rel_loc = format_display_path(path, target_dir)
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_cfg}",
                        "type": "nginx",
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )
            findings.extend(self.scan_file(path))

        return findings

    def scan_file(self, file_path: Path) -> List[NginxFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        findings: List[NginxFinding] = []

        # Find all server { ... } blocks
        for match in SERVER_BLOCK_REGEX.finditer(content):
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1
            block_body = self._extract_block_body(content, match.end())

            finding = self._evaluate_server_block(file_path, line_no, block_body)
            if finding:
                findings.append(finding)

        # Fallback: file without explicit server blocks (e.g. ssl.conf snippet)
        if not findings and ("ssl_protocols" in content or "ssl_ciphers" in content):
            finding = self._evaluate_server_block(file_path, 1, content)
            if finding:
                findings.append(finding)

        return findings

    def _extract_block_body(self, content: str, start_index: int) -> str:
        brace_depth = 1
        body_chars = []
        for char in content[start_index:]:
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    break
            body_chars.append(char)
        return "".join(body_chars)

    def _evaluate_server_block(self, file_path: Path, line_no: int, block: str) -> Optional[NginxFinding]:
        directives: Dict[str, str] = {}
        for m in DIRECTIVE_REGEX.finditer(block):
            k = m.group("key")
            v = m.group("val").strip()
            directives[k] = v

        if not any(k.startswith("ssl_") for k in directives):
            return None

        sec_findings = []
        protocols = [p.strip() for p in directives.get("ssl_protocols", "TLSv1.2 TLSv1.3").split()]
        ciphers = directives.get("ssl_ciphers", "")
        ecdh_curve = directives.get("ssl_ecdh_curve", "")

        matched_insecure = self.insecure_tls_versions.intersection(set(protocols))
        if matched_insecure:
            sec_findings.append({
                "issue": f"Legacy, insecure TLS protocols enabled: {', '.join(sorted(matched_insecure))}",
                "severity": "CRITICAL"
            })

        for token in self.insecure_cipher_tokens:
            if re.search(rf"\b{token}\b", ciphers, re.IGNORECASE):
                sec_findings.append({
                    "issue": f"Broken/insecure cipher token configured in ssl_ciphers: {token}",
                    "severity": "HIGH"
                })

        quantum_safe = False
        shor_vuln = True
        if "kyber" in ecdh_curve.lower() or "mlkem" in ecdh_curve.lower():
            quantum_safe = True
            shor_vuln = False

        return NginxFinding(
            source_domain="network",
            config_type="nginx",
            file_path=str(file_path.resolve()),
            line_number=line_no,
            server_name=directives.get("server_name", "default"),
            listen_port=directives.get("listen", "443"),
            protocols=protocols,
            ciphers=ciphers,
            ecdh_curve=ecdh_curve,
            certificate_path=directives.get("ssl_certificate"),
            certificate_key_path=directives.get("ssl_certificate_key"),
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={
                "prefer_server_ciphers": directives.get("ssl_prefer_server_ciphers", "off")
            }
        )