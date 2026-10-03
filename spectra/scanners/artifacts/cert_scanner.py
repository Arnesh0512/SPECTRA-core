"""
spectra.scanners.artifacts.cert_scanner
============================================
Discovers and inspects X.509 digital certificates and private key files on disk.
Evaluates signature algorithms, public key types, key lengths, expiration horizons,
and Shor quantum vulnerability.
Loaded via rules/artifact_patterns.yaml.
"""

import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import yaml

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448

try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass


@dataclass
class CertFinding:
    """Represents a discovered certificate or key artifact."""
    source_domain: str = "artifacts"
    artifact_type: str = "x509_certificate"
    is_system_ca: bool = False
    file_path: str = ""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_valid_before: Optional[str] = None
    not_valid_after: Optional[str] = None
    days_to_expiration: Optional[int] = None
    signature_algorithm: str = "unknown"
    public_key_algorithm: str = "unknown"
    key_size: Optional[int] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "is_system_ca": self.is_system_ca,
            "file_path": self.file_path,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before,
            "not_valid_after": self.not_valid_after,
            "days_to_expiration": self.days_to_expiration,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


class CertScanner:
    """Scans directories for certificates, keystores, and keys using rules/artifact_patterns.yaml."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "artifact_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        self.cert_extensions = set(self.rules.get("file_extensions", {
            ".pem": "pem_file", ".crt": "certificate_file", ".cer": "certificate_file",
            ".key": "private_key_file", ".jks": "java_keystore", ".p12": "pkcs12_keystore"
        }).keys())
        self.special_filenames = set(self.rules.get("special_filenames", {}).keys())

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
        include_system_certs: bool = False,
        progress_callback: Optional[Callable] = None,
    ) -> List[CertFinding]:
        findings: List[CertFinding] = []
        excluded = set(excluded_dirs or [])

        from spectra.utils.system_paths import get_certificate_system_paths, is_preinstalled_system_ca
        search_dirs: List[Path] = [target_dir] if target_dir and target_dir.exists() else []
        for sys_path in get_certificate_system_paths(target_dir, include_system_certs=include_system_certs):
            if sys_path not in search_dirs and not any(part in excluded for part in sys_path.parts):
                search_dirs.append(sys_path)

        matching_files: List[Path] = []
        seen_files: Set[str] = set()
        import os
        for sdir in search_dirs:
            try:
                for root, dirs, files in os.walk(str(sdir)):
                    dirs[:] = [
                        d for d in dirs
                        if d not in excluded and not any(part in excluded for part in Path(root, d).parts)
                    ]
                    for file_name in files:
                        p = Path(root) / file_name
                        p_key = str(p.resolve() if not str(p).startswith("/proc/") else p)
                        if p_key in seen_files:
                            continue
                        suffix = p.suffix.lower()
                        name = p.name.lower()
                        if suffix in self.cert_extensions or name in self.special_filenames:
                            # Skip default system openssl.cnf when outside target perimeter
                            if name == "openssl.cnf":
                                in_target = False
                                if target_dir:
                                    try:
                                        t_str = str(target_dir.resolve() if not str(target_dir).startswith("/proc/") else target_dir).replace("\\", "/")
                                        p_str = str(p.resolve() if not str(p).startswith("/proc/") else p).replace("\\", "/")
                                        in_target = p_str.startswith(t_str.rstrip("/") + "/")
                                    except Exception:
                                        pass
                                if not in_target:
                                    continue
                            # If system certs are disabled, fast-bypass known system bundles and symlinks
                            if not include_system_certs and is_preinstalled_system_ca(p, target_dir=target_dir):
                                continue
                            seen_files.add(p_key)
                            matching_files.append(p)
            except Exception:
                pass

        total_certs = len(matching_files)
        for idx, path in enumerate(matching_files, start=1):
            is_sys_cand = is_preinstalled_system_ca(path, target_dir=target_dir)
            item_type = "system ca" if is_sys_cand else "certificate"
            label = "OS Root CA" if is_sys_cand else "Certificate"

            if progress_callback and total_certs > 0:
                pct = 45.0 + (idx / total_certs) * 7.0
                desc = f"Domain 2/4: Auditing {label} ({idx}/{total_certs}) {path.name}"
                try:
                    rel_loc = str(path.relative_to(target_dir)).replace("\\", "/")
                except Exception:
                    rel_loc = str(path).replace("\\", "/")
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_certs}",
                        "type": item_type,
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )
            finding = self.scan_file(path, target_dir=target_dir, include_system_certs=include_system_certs)
            if finding:
                findings.append(finding)

        return findings

    def scan_file(
        self,
        file_path: Path,
        target_dir: Optional[Path] = None,
        include_system_certs: bool = False,
    ) -> Optional[CertFinding]:
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Attempt X.509 Certificate parsing
            try:
                cert = x509.load_pem_x509_certificate(data, default_backend())
                return self._parse_x509_cert(file_path, cert, target_dir=target_dir, include_system_certs=include_system_certs)
            except Exception:
                try:
                    cert = x509.load_der_x509_certificate(data, default_backend())
                    return self._parse_x509_cert(file_path, cert, target_dir=target_dir, include_system_certs=include_system_certs)
                except Exception:
                    pass

            # Fallback for keys / keystores where X.509 certificate parsing doesn't apply directly
            return self._parse_non_cert_artifact(file_path, data)
        except Exception:
            return None

    def _parse_x509_cert(
        self,
        file_path: Path,
        cert: x509.Certificate,
        target_dir: Optional[Path] = None,
        include_system_certs: bool = False,
    ) -> Optional[CertFinding]:
        from spectra.utils.system_paths import is_preinstalled_system_ca
        is_sys_ca = is_preinstalled_system_ca(file_path, target_dir=target_dir, cert=cert)
        if is_sys_ca and not include_system_certs:
            return None

        sec_findings = []
        now = datetime.now(timezone.utc)

        # Subject & Issuer
        subject_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()

        # Dates & Expiration
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_left = (not_after - now).days

        if days_left < 0:
            sec_findings.append({
                "issue": f"Certificate expired {abs(days_left)} day(s) ago",
                "severity": "CRITICAL"
            })
        elif days_left < 30:
            sec_findings.append({
                "issue": f"Certificate expiring soon ({days_left} days remaining)",
                "severity": "MEDIUM"
            })

        # Signature Algorithm check
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        if sig_algo.lower() in ["md5", "sha1"]:
            sec_findings.append({
                "issue": f"Cryptographically broken signature digest used: {sig_algo.upper()}",
                "severity": "HIGH"
            })

        # Public Key Extraction
        pub_key = cert.public_key()
        key_algo, key_size, shor_vuln = self._inspect_public_key(pub_key)

        if key_algo == "RSA" and key_size and key_size < 2048:
            sec_findings.append({
                "issue": f"Weak RSA key length ({key_size} bits); minimum recommended is 2048 bits",
                "severity": "HIGH"
            })

        artifact_type = "system_root_ca" if is_sys_ca else "x509_certificate"
        if is_sys_ca:
            sec_findings.append({
                "issue": "Preinstalled OS vendor root CA (/etc/ssl/certs)",
                "severity": "LOW"
            })

        return CertFinding(
            source_domain="artifacts",
            artifact_type=artifact_type,
            is_system_ca=is_sys_ca,
            file_path=str(file_path.resolve()),
            subject=subject_str,
            issuer=issuer_str,
            serial_number=hex(cert.serial_number),
            not_valid_before=not_before.isoformat(),
            not_valid_after=not_after.isoformat(),
            days_to_expiration=days_left,
            signature_algorithm=sig_algo.upper(),
            public_key_algorithm=key_algo,
            key_size=key_size,
            quantum_safe=not shor_vuln,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={
                "version": cert.version.name,
                "is_system_ca": is_sys_ca,
                "scope": "system_trust_store" if is_sys_ca else "application",
            }
        )

    def _parse_non_cert_artifact(self, file_path: Path, data: bytes) -> CertFinding:
        """Handles private keys, keystores, and CSRs safely without leaking secrets."""
        text = data.decode("utf-8", errors="ignore")
        artifact_type = "private_key" if "PRIVATE KEY" in text or file_path.suffix.lower() == ".key" else "keystore"
        
        return CertFinding(
            source_domain="artifacts",
            artifact_type=artifact_type,
            is_system_ca=False,
            file_path=str(file_path.resolve()),
            subject=file_path.name,
            issuer="Local Artifact",
            serial_number="N/A",
            signature_algorithm="N/A",
            public_key_algorithm="RSA/ECC",
            key_size=2048,
            quantum_safe=False,
            shor_vulnerable=True,
            security_findings=[{
                "issue": f"Discovered cryptographic artifact file ({file_path.name})",
                "severity": "MEDIUM"
            }],
            raw_metadata={"artifact_category": artifact_type, "is_system_ca": False, "scope": "application"}
        )

    def _inspect_public_key(self, pub_key: Any) -> tuple[str, Optional[int], bool]:
        """Returns (algorithm_name, bit_length, is_shor_vulnerable)."""
        if isinstance(pub_key, rsa.RSAPublicKey):
            return "RSA", pub_key.key_size, True
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            return f"ECC-{pub_key.curve.name}", pub_key.key_size, True
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return "DSA", pub_key.key_size, True
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, True
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            return "Ed448", 448, True
        elif isinstance(pub_key, x25519.X25519PublicKey):
            return "X25519", 256, True
        elif isinstance(pub_key, x448.X448PublicKey):
            return "X448", 448, True
        return "Unknown", None, True