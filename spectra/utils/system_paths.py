"""
spectra.utils.system_paths
==========================
Discovers system-level and mounted root directories across OS environments
(Linux, Windows, macOS, WSL, Docker container mounts) and locates default
system configurations for Nginx, Apache, OpenSSL, and X.509 certificates.
Also provides advanced multi-port endpoint parsing.
"""

import os
from pathlib import Path
import platform
import re
import sys
from typing import Any, List, Optional, Set


def discover_root_mounts(target_dir: Optional[Path] = None) -> List[Path]:
    """
    Identifies all candidate root directories across environments:
    - Container process filesystem (/proc/<pid>/root)
    - Container extracted archive (/tmp/spectra_containers/<name>)
    - Docker container host volume mounts (/scan, /host, /target)
    - Native host root (/, C:/, D:/, etc.)
    - WSL mounted drives (/mnt/c, /mnt/d, etc.)
    """
    roots: List[Path] = []
    seen: Set[str] = set()

    def _add_root(p: Optional[Path]):
        if not p:
            return
        try:
            resolved = p.resolve() if not str(p).startswith("/proc/") else p
            res_str = str(resolved).rstrip("/\\")
            if not res_str:
                res_str = "/"
            if res_str not in seen and p.exists() and p.is_dir():
                seen.add(res_str)
                roots.append(p)
        except Exception:
            pass

    # 1. Inspect target_dir hierarchy
    if target_dir:
        t_str = str(target_dir).replace("\\", "/")
        # Fast-path container proc mount: /proc/<pid>/root/...
        proc_match = re.match(r"^(/proc/\d+/root)", t_str)
        if proc_match:
            _add_root(Path(proc_match.group(1)))
        
        # Extracted container staging directory: /tmp/spectra_containers/<name>/...
        tmp_match = re.match(r"^(/tmp/spectra_containers/[^/]+)", t_str)
        if tmp_match:
            _add_root(Path(tmp_match.group(1)))

        # Direct root anchor
        if target_dir.anchor:
            _add_root(Path(target_dir.anchor))

    # 2. Check Docker container mounts of host filesystem
    for mount_cand in [Path("/scan"), Path("/host"), Path("/target"), Path("/var/run")]:
        if mount_cand.exists() and mount_cand.is_dir():
            _add_root(mount_cand)

    # 3. Check /proc/self/mountinfo if running inside Linux/Docker
    mountinfo = Path("/proc/self/mountinfo")
    if mountinfo.exists():
        try:
            for line in mountinfo.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    mp = Path(parts[4])
                    # If mounted directory looks like a root or host volume
                    if mp.name in ["scan", "host", "target", "mnt", "root"]:
                        _add_root(mp)
        except Exception:
            pass

    # 4. Check native OS roots
    system = platform.system()
    if system == "Windows":
        # Check all available Windows drive letters
        import string
        for letter in string.ascii_uppercase:
            drive_path = Path(f"{letter}:/")
            if drive_path.exists():
                _add_root(drive_path)
    else:
        # Linux, macOS, Unix
        _add_root(Path("/"))
        # Check common WSL drive mounts
        for wsl_drive in [Path("/mnt/c"), Path("/mnt/d"), Path("/mnt/e")]:
            if wsl_drive.exists():
                _add_root(wsl_drive)
        # Check macOS volume roots
        for mac_vol in [Path("/System/Volumes/Data"), Path("/Volumes")]:
            if mac_vol.exists():
                _add_root(mac_vol)

    return roots


def get_webserver_config_paths(target_dir: Optional[Path] = None) -> List[Path]:
    """
    Returns all existing directories likely to contain Nginx, Apache, or web server
    configuration files, scanning both target_dir and all discovered root mounts.
    """
    candidate_paths: List[Path] = []
    seen: Set[str] = set()

    def _add_path(p: Path):
        try:
            if p.exists() and p.is_dir():
                key = str(p.resolve() if not str(p).startswith("/proc/") else p)
                if key not in seen:
                    seen.add(key)
                    candidate_paths.append(p)
        except Exception:
            pass

    # Check target_dir directly
    if target_dir and target_dir.exists():
        _add_path(target_dir)
        # Check common subdirectories in project
        for sub in ["network/nginx", "network/nginx/conf.d", "nginx", "conf.d", "config/nginx"]:
            _add_path(target_dir / sub)

    # Search standard web server locations across all discovered roots
    subdirs = [
        "etc/nginx",
        "etc/nginx/conf.d",
        "usr/local/etc/nginx",
        "usr/local/etc/nginx/conf.d",
        "opt/nginx/conf",
        "opt/homebrew/etc/nginx",
        "etc/httpd/conf",
        "etc/apache2",
        "nginx/conf",
        "Program Files/nginx/conf",
        "Program Files (x86)/nginx/conf",
    ]

    for root in discover_root_mounts(target_dir):
        for sub in subdirs:
            _add_path(root / sub)

    return candidate_paths


def get_certificate_system_paths(
    target_dir: Optional[Path] = None,
    include_system_certs: bool = False,
) -> List[Path]:
    """
    Returns all existing directories likely to contain system SSL/TLS certificates,
    private keys, and custom CA trust stores across target_dir and all discovered roots.
    When include_system_certs is False, OS vendor public root CA directories
    (e.g., usr/share/ca-certificates) are completely excluded.
    """
    candidate_paths: List[Path] = []
    seen: Set[str] = set()

    def _add_path(p: Path):
        try:
            if p.exists() and p.is_dir():
                key = str(p.resolve() if not str(p).startswith("/proc/") else p)
                if key not in seen:
                    seen.add(key)
                    candidate_paths.append(p)
        except Exception:
            pass

    # Check target_dir directly
    if target_dir and target_dir.exists():
        _add_path(target_dir)
        for sub in ["certificates", "keys", "certs", "ssl"]:
            _add_path(target_dir / sub)

    # Search standard SSL certificate and key locations across all discovered roots
    subdirs = [
        "etc/ssl/certs",
        "etc/ssl/keys",
        "etc/ssl/private",
        "etc/ssl",
        "etc/pki/tls/certs",
        "etc/pki/tls/private",
        "usr/local/share/ca-certificates",
        "var/ssl",
        "Program Files/OpenSSL-Win64",
        "Program Files/Common Files/SSL",
    ]

    # Only include preinstalled OS vendor trust store repositories if requested
    if include_system_certs:
        subdirs.extend([
            "usr/share/ca-certificates",
            "etc/pki/ca-trust",
            "etc/ca-certificates",
        ])

    for root in discover_root_mounts(target_dir):
        for sub in subdirs:
            _add_path(root / sub)

    return candidate_paths


OS_BUNDLE_FILENAMES = {
    "ca-certificates.crt",
    "ca-bundle.crt",
    "ca-bundle.trust.crt",
    "email-ca-bundle.pem",
    "objsign-ca-bundle.pem",
    "java-cacerts.jks",
    "tls-ca-bundle.pem",
}

KNOWN_PUBLIC_CA_TOKENS = {
    "digicert", "globalsign", "sectigo", "godaddy", "entrust", "amazon",
    "microsoft", "google trust services", "gts", "isrg root", "let's encrypt",
    "lets encrypt", "baltimore", "verisign", "comodo", "d-trust", "buypass",
    "harica", "certum", "swisssign", "identrust", "telia", "tubitak",
    "taiwan electronic", "hongkong post", "oiste", "quovadis", "chunghwa",
    "actalis", "sk id solutions", "affirmtrust", "emsign", "vtrus", "bjca",
    "ca disig", "certigna", "globaltrust", "szafir", "hipki", "anet",
    "ac cv", "fnmt-rcm", "netlock", "securesign", "certsign", "usertrust",
    "commscope", "telekom security", "starfield", "tuntrust", "t-telesec",
    "xramp", "hellenic academic", "securetrust", "twca", "autoridad de certificacion",
    "firmaprofesional", "uca extended", "uca global", "naver global", "izenpe",
    "epki root", "microsec", "secom", "cfca", "ssl.com", "trustwave", "atos",
    "certainly", "gdca", "e-szigno", "trustasia", "security communication"
}


def is_preinstalled_system_ca(
    file_path: Path,
    target_dir: Optional[Path] = None,
    cert: Optional[Any] = None,
) -> bool:
    """
    Differentiates between preinstalled OS vendor Root CAs (e.g., Mozilla CA store)
    and user/application-configured certificates and keys.
    """
    p_str = str(file_path).replace("\\", "/")
    p_lower = p_str.lower()
    name_lower = file_path.name.lower()

    # 1. Any artifact within the project target perimeter is ALWAYS user/application
    if target_dir:
        try:
            t_resolved = str(target_dir.resolve()).replace("\\", "/") if not str(target_dir).startswith("/proc/") else str(target_dir).replace("\\", "/")
            f_resolved = str(file_path.resolve()).replace("\\", "/") if not str(file_path).startswith("/proc/") else p_str
            if f_resolved.startswith(t_resolved.rstrip("/") + "/"):
                return False
        except Exception:
            pass

    # 2. Private keys, keystores, and SSH credentials are NEVER preinstalled OS root CAs
    if (
        name_lower.endswith(".key")
        or name_lower.endswith(".p12")
        or name_lower.endswith(".jks")
        or "private" in name_lower
        or "id_rsa" in name_lower
        or "id_ed25519" in name_lower
        or "/keys/" in p_lower
        or "/private/" in p_lower
    ):
        return False

    # 3. Known monolithic OS CA bundle files
    if name_lower in OS_BUNDLE_FILENAMES:
        return True

    # 4. Known OS vendor CA store directories and paths - ALWAYS preinstalled system CA
    if "/mozilla/" in p_lower:
        return True
    if "/usr/share/ca-certificates/" in p_lower and "/usr/local/" not in p_lower:
        return True
    if any(tok in p_lower for tok in [
        "/ca-certificates/extracted/",
        "/pki/ca-trust-source/",
        "/pki/ca-trust/extracted/",
        "/etc/ca-certificates/",
    ]):
        return True

    # 5. Check if file is a symlink pointing to OS vendor stores or system bundles
    try:
        if file_path.is_symlink():
            link_target = ""
            try:
                import os
                link_target = str(os.readlink(str(file_path))).replace("\\", "/").lower()
            except Exception:
                pass
            resolved_target = str(file_path.resolve()).replace("\\", "/").lower()
            all_target_str = f"{link_target} {resolved_target}"
            if any(token in all_target_str for token in [
                "/mozilla/",
                "/usr/share/ca-certificates/",
                "/ca-certificates/extracted/",
                "/pki/ca-trust/",
                "ca-certificates.crt",
                "ca-bundle.crt",
            ]):
                return True
    except Exception:
        pass

    # 6. Check if file is located in another system CA path (e.g. /etc/ssl/certs, /etc/pki/tls/certs)
    in_system_ca_path = any(
        sys_token in p_lower for sys_token in [
            "/etc/ssl/certs",
            "/etc/pki/tls/certs",
        ]
    )

    if not in_system_ca_path:
        return False

    # 7. If inside system CA path, inspect certificate properties if available
    if cert:
        from cryptography import x509
        # Check basic constraints
        is_ca = False
        try:
            bc = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc.value.ca
        except Exception:
            pass

        # Check SANs (Subject Alternative Names) - Server/End-Entity certs have DNS SANs
        has_san = False
        try:
            san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            has_san = len(san.value) > 0
        except Exception:
            pass

        # If it is NOT a CA, or has SAN hostnames, it is a user/service server cert!
        if not is_ca or has_san:
            return False

        # If it is a CA, check if it's a known public CA or custom user CA
        try:
            subj = cert.subject.rfc4514_string().lower()
            # If "nexis" or project/internal names are in the subject, it's a user CA
            if any(internal_kw in subj for internal_kw in ["nexis", "internal", "local", "corp", "private", "test", "dev", "myca", "custom"]):
                return False
            # Check subject and issuer
            issuer = cert.issuer.rfc4514_string().lower()
            if any(pub_token in subj or pub_token in issuer or pub_token in name_lower for pub_token in KNOWN_PUBLIC_CA_TOKENS):
                return True
            # In /etc/ssl/certs, a CA without internal naming is typically an OS root CA
            return True
        except Exception:
            pass

    # If it's in /etc/ssl/certs without cert obj yet, check filename tokens
    if any(pub_token in name_lower for pub_token in KNOWN_PUBLIC_CA_TOKENS):
        return True

    return False


def parse_endpoint_targets(raw_input: str) -> List[str]:
    """
    Parses endpoint input supporting multiple formats and multi-port syntax:
    - Standard repeated: 'example.com:443, example.com:8443'
    - Multi-port colon list: 'example.com:443,8443' or 'example.com:443;8443' or 'example.com:443/8443'
    - Bare port following a domain: 'example.com:443, 8443'
    - Bare domain without port: 'example.com' -> 'example.com:443'
    """
    if not raw_input or not raw_input.strip():
        return []

    endpoints: List[str] = []
    last_host: Optional[str] = None

    tokens = [t.strip() for t in re.split(r"[,;\s]+", raw_input) if t.strip()]

    for token in tokens:
        clean_token = re.sub(r"^https?://", "", token).rstrip("/")
        
        # Check if token is just a port number (e.g. "8443" following "example.com:443")
        if clean_token.isdigit() and last_host:
            port = int(clean_token)
            endpoints.append(f"{last_host}:{port}")
            continue

        # Check if token has multiple ports attached, e.g. "example.com:443/8443" or "example.com:443|8443"
        if ":" in clean_token:
            parts = clean_token.split(":")
            host = parts[0]
            ports_str = ":".join(parts[1:])
            port_candidates = re.split(r"[/|]+", ports_str)
            last_host = host
            for pc in port_candidates:
                try:
                    port = int(pc.strip())
                    endpoints.append(f"{host}:{port}")
                except ValueError:
                    endpoints.append(f"{host}:443")
        else:
            last_host = clean_token
            endpoints.append(f"{clean_token}:443")

    seen = set()
    deduped = []
    for ep in endpoints:
        if ep not in seen:
            seen.add(ep)
            deduped.append(ep)
    return deduped
