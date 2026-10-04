"""
spectra.scanners.infrastructure.docker_scanner
==============================================
Static container manifest and Dockerfile scanner for infrastructure domain.
Audits Dockerfiles, Containerfiles, and build manifests for embedded credentials,
insecure TLS environment configurations, and referenced certificate/key assets.
Loaded via rules/docker_patterns.yaml.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional
import yaml


@dataclass
class DockerFinding:
    """Represents cryptographic evidence discovered within Dockerfiles or container definitions."""
    source_domain: str = "infrastructure"
    infra_provider: str = "docker"
    file_path: str = ""
    line_number: int = 1
    resource_kind: str = "dockerfile"
    resource_name: str = ""
    finding_category: str = "embedded_crypto"
    details: str = ""
    algorithm: str = "unknown"
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "infra_provider": self.infra_provider,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "finding_category": self.finding_category,
            "details": self.details,
            "algorithm": self.algorithm,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class DockerScanner:
    """Discovers and audits Dockerfiles and container build recipes within the Infrastructure domain."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "docker_patterns.yaml"
        self.rules = self._load_rules(rules_file)

        self.dockerfile_names = set(self.rules.get("dockerfile_names", ["dockerfile", "containerfile"]))
        self.dockerfile_extensions = set(self.rules.get("dockerfile_extensions", [".dockerfile", ".containerfile"]))

        key_pats = self.rules.get("embedded_key_patterns", [r"----[-]?BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY----[-]?"])
        self.embedded_key_regex = re.compile("|".join(key_pats), re.MULTILINE)

        copy_pats = self.rules.get("copy_key_patterns", [r"^\s*(?:COPY|ADD)\s+.*?\.(?:key|pem|p12|pfx|pkcs12|crt|cer)\b"])
        self.copy_key_regex = re.compile("|".join(copy_pats), re.MULTILINE | re.IGNORECASE)

        env_pat = self.rules.get("env_crypto_patterns", [r"^\s*ENV\s+(?P<var>SSL_CIPHER_SUITES|OPENSSL_CONF|NODE_OPTIONS|TLS_MIN_VERSION)\s*=?\s*(?P<val>[^\n]+)"])
        self.env_crypto_regex = re.compile("|".join(env_pat) if isinstance(env_pat, list) else env_pat, re.MULTILINE)

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[DockerFinding]:
        findings: List[DockerFinding] = []
        excluded = set(excluded_dirs or [])

        docker_files: List[Path] = []
        try:
            for root, dirs, files in os.walk(str(target_dir)):
                dirs[:] = [
                    d for d in dirs
                    if d not in excluded and not any(part in excluded for part in Path(root, d).parts)
                ]
                for file_name in files:
                    p = Path(root) / file_name
                    if p.name.lower() in self.dockerfile_names or p.suffix.lower() in self.dockerfile_extensions:
                        docker_files.append(p)
        except Exception:
            pass

        total_cnt = len(docker_files)
        for idx, path in enumerate(docker_files, start=1):
            if progress_callback and total_cnt > 0:
                pct = 42.0 + (idx / total_cnt) * 3.0
                desc = f"Domain 2/4: Auditing Dockerfile ({idx}/{total_cnt}) {path.name}"
                from spectra.utils.system_paths import format_display_path
                rel_loc = format_display_path(path, target_dir)
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_cnt}",
                        "type": "dockerfile",
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )
            findings.extend(self.scan_file(path, target_dir=target_dir))

        return findings

    def scan_file(self, file_path: Path, target_dir: Optional[Path] = None) -> List[DockerFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        findings: List[DockerFinding] = []

        from spectra.utils.system_paths import format_display_path
        clean_file_path = format_display_path(file_path, target_dir)

        # Harvest all referenced certificate and key file paths in the Dockerfile
        cert_matches = re.findall(
            r'["\']?([^"\'\s\n\(\)]+\.(?:crt|pem|cer|key|p12|jks))["\']?',
            content,
            re.IGNORECASE
        )

        # 1. Inspect for embedded private key blocks
        for match in self.embedded_key_regex.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            findings.append(DockerFinding(
                source_domain="infrastructure",
                infra_provider="docker",
                file_path=clean_file_path,
                line_number=line_no,
                resource_kind="dockerfile",
                resource_name=file_path.name,
                finding_category="embedded_crypto",
                details="Hardcoded private key block detected directly inside Dockerfile",
                algorithm="RSA/ECC",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[{
                    "issue": "Private key material is baked into container image layers",
                    "severity": "CRITICAL"
                }],
                raw_metadata={"directive": "RUN/EMBEDDED", "host_path": str(file_path)}
            ))

        # 2. Inspect COPY/ADD directives copying sensitive key files
        for match in self.copy_key_regex.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            matched_line = match.group(0).strip()
            findings.append(DockerFinding(
                source_domain="infrastructure",
                infra_provider="docker",
                file_path=clean_file_path,
                line_number=line_no,
                resource_kind="dockerfile",
                resource_name=file_path.name,
                finding_category="copied_key",
                details=f"Copying private key artifact into image: '{matched_line}'",
                algorithm="Private-Key",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[{
                    "issue": "Sensitive private key files copied into container filesystem layer",
                    "severity": "HIGH"
                }],
                raw_metadata={"matched_instruction": matched_line, "host_path": str(file_path)}
            ))

        # 3. Inspect ENV variables configuring TLS or OpenSSL
        for match in self.env_crypto_regex.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            var_name = match.group("var")
            var_val = match.group("val").strip()

            sec_findings = []
            if "legacy" in var_val.lower() or "tlsv1" in var_val.lower():
                sec_findings.append({
                    "issue": f"Container environment sets legacy/weak TLS configuration: {var_name}={var_val}",
                    "severity": "HIGH"
                })

            findings.append(DockerFinding(
                source_domain="infrastructure",
                infra_provider="docker",
                file_path=clean_file_path,
                line_number=line_no,
                resource_kind="dockerfile",
                resource_name=file_path.name,
                finding_category="env_crypto",
                details=f"Dockerfile environment crypto directive: {var_name}={var_val}",
                algorithm=var_val if len(var_val) < 20 else "Custom-TLS-Env",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=sec_findings,
                raw_metadata={"variable": var_name, "value": var_val, "host_path": str(file_path)}
            ))

        # 4. Attach referenced certificates to findings or register the Dockerfile itself
        if cert_matches:
            for f in findings:
                f.raw_metadata.setdefault("referenced_cert_paths", []).extend(cert_matches)

            if not findings:
                findings.append(DockerFinding(
                    source_domain="infrastructure",
                    infra_provider="docker",
                    file_path=clean_file_path,
                    line_number=1,
                    resource_kind="dockerfile",
                    resource_name=file_path.name,
                    finding_category="container_definition",
                    details=f"Dockerfile declares cryptographic asset references ({len(cert_matches)} found)",
                    algorithm="Dockerfile-Environment",
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=[],
                    raw_metadata={"referenced_cert_paths": cert_matches, "host_path": str(file_path)}
                ))
        elif not findings:
            # Baseline entry for clean Dockerfile
            findings.append(DockerFinding(
                source_domain="infrastructure",
                infra_provider="docker",
                file_path=clean_file_path,
                line_number=1,
                resource_kind="dockerfile",
                resource_name=file_path.name,
                finding_category="container_definition",
                details="Standard container image definition",
                algorithm="Standard-Container",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[],
                raw_metadata={"host_path": str(file_path)}
            ))

        return findings
