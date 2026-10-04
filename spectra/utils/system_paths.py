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
            resolved = p if "/proc/" in str(p) else p.resolve()
            res_str = str(resolved).rstrip("/\\")
            if not res_str:
                res_str = "/"
            if res_str not in seen and p.exists() and p.is_dir():
                seen.add(res_str)
                roots.append(p)
        except Exception:
            pass

    # 1. Inspect target_dir hierarchy and candidate mounted root filesystems
    if target_dir:
        t_str = str(target_dir).replace("\\", "/")
        # Fast-path container proc mount: /proc/<pid>/root/... or /scan/proc/<pid>/root/... or /host/proc/<pid>/root/...
        proc_match = re.match(r"^((?:/(?:scan|host))?/proc/\d+/root)", t_str)
        if proc_match:
            _add_root(Path(proc_match.group(1)))
        
        # Extracted container staging directory: /tmp/spectra_containers/<name>/...
        tmp_match = re.match(r"^(/tmp/spectra_containers/[^/]+)", t_str)
        if tmp_match:
            _add_root(Path(tmp_match.group(1)))

        # Direct root anchor (e.g., /, C:\)
        if target_dir.anchor:
            _add_root(Path(target_dir.anchor))

        # Inspect target_dir and its parent directories to identify mounted root filesystems
        # (directories containing system structures like etc, usr, Program Files, Windows, or Library)
        try:
            cand_dirs = [target_dir]
            if "/proc/" not in str(target_dir):
                cand_dirs.extend(list(target_dir.resolve().parents))
            else:
                cand_dirs.extend(list(target_dir.parents))
            for cand in cand_dirs:
                if any(
                    (cand / ind).is_dir()
                    for ind in ["etc", "usr", "Program Files", "Program Files (x86)", "Windows", "Library", "System"]
                ):
                    _add_root(cand)
        except Exception:
            pass

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
                    if mp.is_dir() and mp.name in ["scan", "host", "target", "mnt", "root", "media"]:
                        _add_root(mp)
        except Exception:
            pass

    # 4. Check native OS roots, mounted drives, and volumes across platforms
    system = platform.system()
    if system == "Windows":
        # Check all available Windows drive letters (A:\ through Z:\)
        import string
        for letter in string.ascii_uppercase:
            drive_path = Path(f"{letter}:/")
            if drive_path.exists():
                _add_root(drive_path)
    else:
        # Linux, macOS, Unix native root
        _add_root(Path("/"))

        # Linux/WSL mounted drives (/mnt/*, /media/*, /run/media/*)
        for mount_parent in [Path("/mnt"), Path("/media"), Path("/run/media")]:
            if mount_parent.exists() and mount_parent.is_dir():
                try:
                    for sub in mount_parent.iterdir():
                        if sub.is_dir():
                            _add_root(sub)
                except Exception:
                    pass

        # macOS volume roots (/Volumes/*, /System/Volumes/Data, /Library)
        mac_vols = Path("/Volumes")
        if mac_vols.exists() and mac_vols.is_dir():
            try:
                for sub in mac_vols.iterdir():
                    if sub.is_dir():
                        _add_root(sub)
            except Exception:
                pass
        for mac_vol in [Path("/System/Volumes/Data"), Path("/Library")]:
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
                key = str(p if "/proc/" in str(p) else p.resolve())
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


def get_protocol_config_paths(target_dir: Optional[Path] = None) -> List[Path]:
    """
    Returns all existing directories likely to contain SSH (server & client) or IPsec
    configuration files, scanning target_dir, user home directories, and all discovered roots
    (Linux, WSL, Windows, macOS, container mounts).
    """
    candidate_paths: List[Path] = []
    seen: Set[str] = set()

    def _add_path(p: Path):
        try:
            if p.exists() and p.is_dir():
                key = str(p if "/proc/" in str(p) else p.resolve())
                if key not in seen:
                    seen.add(key)
                    candidate_paths.append(p)
        except Exception:
            pass

    # 1. Target directory and common project/container convention subdirectories
    if target_dir and target_dir.exists():
        _add_path(target_dir)
        for sub in [
            "network/ssh", "network/ipsec", "deployments/ssh", "deployments/docker/ssh",
            "deployments/vpn", "config/ssh", "configs/ssh", "ssh", ".ssh", ".devcontainer"
        ]:
            _add_path(target_dir / sub)

    # 2. System and host SSH/IPsec locations across all discovered roots
    subdirs = [
        # Linux & Unix system locations
        "etc/ssh",
        "etc/ssh/sshd_config.d",
        "etc/ssh/ssh_config.d",
        "etc/ipsec.d",
        "etc/strongswan",
        "etc/strongswan.d",
        "usr/local/etc/ssh",
        "opt/homebrew/etc/ssh",
        "private/etc/ssh",

        # Windows OpenSSH system locations
        "ProgramData/ssh",
        "Windows/System32/OpenSSH",
    ]

    for root in discover_root_mounts(target_dir):
        for sub in subdirs:
            _add_path(root / sub)

        # Root user SSH folder
        _add_path(root / "root/.ssh")
        _add_path(root / "var/root/.ssh")

        # Discover all user home directories on this root (Linux/WSL /home/<user>/.ssh)
        home_dir = root / "home"
        if home_dir.exists() and home_dir.is_dir():
            try:
                for u_dir in home_dir.iterdir():
                    if u_dir.is_dir() and not u_dir.name.startswith("."):
                        _add_path(u_dir / ".ssh")
            except Exception:
                pass

        # Discover all user home directories on this root (Windows/macOS /Users/<user>/.ssh)
        users_dir = root / "Users"
        if users_dir.exists() and users_dir.is_dir():
            try:
                for u_dir in users_dir.iterdir():
                    if u_dir.is_dir() and not u_dir.name.startswith("."):
                        _add_path(u_dir / ".ssh")
            except Exception:
                pass

    # 3. Current execution user's home directory across OSes
    try:
        user_home = Path.home()
        if user_home.exists():
            _add_path(user_home / ".ssh")
            _add_path(user_home / "ssh")
    except Exception:
        pass

    # 4. Host user environment variable if running inside container (-e HOST_USER=$USER)
    host_user = os.environ.get("HOST_USER")
    if host_user:
        for u_cand in [Path(f"/home/{host_user}/.ssh"), Path(f"/scan/home/{host_user}/.ssh"), Path(f"/host/home/{host_user}/.ssh")]:
            _add_path(u_cand)

    return candidate_paths


def get_certificate_system_paths(
    target_dir: Optional[Path] = None,
    include_system_certs: bool = False,
) -> List[Path]:
    """
    Returns all existing directories likely to contain system SSL/TLS certificates,
    private keys, and custom CA trust stores across target_dir and all discovered roots
    (Linux, WSL, Windows, macOS, mounted drives).
    When include_system_certs is False, OS vendor public root CA directories
    (e.g., usr/share/ca-certificates, System/Library/Keychains) are completely excluded.
    """
    candidate_paths: List[Path] = []
    seen: Set[str] = set()

    def _add_path(p: Path):
        try:
            if p.exists() and p.is_dir():
                key = str(p if "/proc/" in str(p) else p.resolve())
                if key not in seen:
                    seen.add(key)
                    candidate_paths.append(p)
        except Exception:
            pass

    # 1. Target directory & its standard internal certificate folders
    if target_dir and target_dir.exists():
        _add_path(target_dir)
        for sub in [
            "certificates", "keys", "certs", "ssl", "tls", "pki",
            "keystores", "config/ssl", "config/certs", "conf/ssl", "security"
        ]:
            _add_path(target_dir / sub)

    # 2. Standard SSL certificate and key locations across all discovered roots
    # Comprehensive across Linux, WSL, Windows, macOS, and mounted filesystems
    subdirs = [
        # Linux / WSL / Unix system locations
        "etc/ssl/certs",
        "etc/ssl/keys",
        "etc/ssl/private",
        "etc/ssl",
        "etc/pki/tls/certs",
        "etc/pki/tls/private",
        "etc/pki/tls",
        "etc/pki/ca-trust/source/anchors",
        "usr/local/share/ca-certificates",
        "usr/local/etc/ssl",
        "usr/local/etc/ssl/certs",
        "usr/local/etc/openssl",
        "usr/local/ssl",
        "var/ssl",
        "etc/security/certificates",

        # Windows OpenSSL, Common Files & system SSL locations
        "Program Files/Common Files/SSL",
        "Program Files/Common Files/SSL/certs",
        "Program Files/Common Files/SSL/private",
        "Program Files (x86)/Common Files/SSL",
        "Program Files (x86)/Common Files/SSL/certs",
        "Program Files (x86)/Common Files/SSL/private",
        "Program Files/OpenSSL-Win64",
        "Program Files/OpenSSL-Win64/bin/PEM",
        "Program Files/OpenSSL-Win64/certs",
        "Program Files/OpenSSL-Win64/keys",
        "Program Files (x86)/OpenSSL-Win32",
        "Program Files (x86)/OpenSSL-Win32/certs",
        "Program Files (x86)/OpenSSL-Win32/keys",
        "ProgramData/ssl",
        "ProgramData/ssl/certs",
        "ProgramData/ssl/private",
        "ProgramData/OpenSSL",
        "ProgramData/OpenSSL/certs",
        "ProgramData/certificates",
        "Windows/System32/drivers/etc/ssl",
        "OpenSSL-Win64",
        "OpenSSL-Win64/certs",
        "OpenSSL-Win32",
        "tools/openssl",

        # macOS system & Homebrew SSL locations
        "private/etc/ssl/certs",
        "private/etc/ssl/keys",
        "private/etc/ssl",
        "usr/local/etc/openssl",
        "usr/local/etc/openssl@3",
        "usr/local/etc/openssl@1.1",
        "opt/homebrew/etc/openssl",
        "opt/homebrew/etc/openssl@3",
        "opt/homebrew/etc/openssl@1.1",
        "opt/homebrew/share/ca-certificates",
        "opt/homebrew/etc/ca-certificates",
        "Library/Keychains",
        "Library/Security/Certificates",
    ]

    # Only include preinstalled OS vendor trust store repositories if requested
    if include_system_certs:
        subdirs.extend([
            # Linux OS vendor root CA packages
            "usr/share/ca-certificates",
            "etc/pki/ca-trust",
            "etc/pki/ca-trust/extracted",
            "etc/ca-certificates",
            "etc/ca-certificates/extracted",

            # macOS OS vendor root trust store
            "System/Library/Keychains",
            "System/Library/OpenSSL/certs",

            # Windows system catalog trust stores
            "Windows/System32/catroot",
            "Windows/System32/catroot2",
        ])

    for root in discover_root_mounts(target_dir):
        for sub in subdirs:
            _add_path(root / sub)

    # Search user's security directories (.ssh, .ssl) across OSes
    try:
        user_home = Path.home()
        if user_home.exists():
            for u_sub in [".ssh", ".ssl", "AppData/Roaming/OpenSSL", "AppData/Local/OpenSSL"]:
                _add_path(user_home / u_sub)
    except Exception:
        pass

    return candidate_paths


OS_BUNDLE_FILENAMES = {
    "ca-certificates.crt",
    "ca-bundle.crt",
    "ca-bundle.trust.crt",
    "email-ca-bundle.pem",
    "objsign-ca-bundle.pem",
    "java-cacerts.jks",
    "tls-ca-bundle.pem",
    "cert.pem",
    "curl-ca-bundle.crt",
    "authroot.stl",
    "roots.sst",
}

KNOWN_PUBLIC_CA_TOKENS = {
    # Global Public Root CAs
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
    "certainly", "gdca", "e-szigno", "trustasia", "security communication",
    # Apple Root CAs (macOS)
    "apple root ca", "apple computer", "apple worldwide", "apple public", "apple inc",
    # Windows / Microsoft Root CAs
    "microsoft root certificate authority", "microsoft root ca", "microsoft corporation", "windows root",
    # Linux distribution vendor roots
    "mozilla root", "canonical", "debian", "red hat",
}


def is_preinstalled_system_ca(
    file_path: Path,
    target_dir: Optional[Path] = None,
    cert: Optional[Any] = None,
) -> bool:
    """
    Differentiates between preinstalled OS vendor Root CAs (e.g., Mozilla CA store,
    Windows Root Store, macOS System Keychain) and user/application-configured certificates and keys.
    Works universally across Linux/WSL, Windows, macOS, and mounted filesystems.
    """
    p_str = str(file_path).replace("\\", "/")
    p_lower = p_str.lower()
    name_lower = file_path.name.lower()

    # 1. Any artifact within the project target perimeter is ALWAYS user/application
    if target_dir:
        try:
            t_resolved = str(target_dir if "/proc/" in str(target_dir) else target_dir.resolve()).replace("\\", "/")
            f_resolved = str(file_path if "/proc/" in str(file_path) else file_path.resolve()).replace("\\", "/")
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
    # Covers Linux, macOS, and Windows vendor stores
    if "/mozilla/" in p_lower:
        return True
    if "/usr/share/ca-certificates/" in p_lower and "/usr/local/" not in p_lower:
        return True
    if any(tok in p_lower for tok in [
        "/ca-certificates/extracted/",
        "/pki/ca-trust-source/",
        "/pki/ca-trust/extracted/",
        "/etc/ca-certificates/",
        "/system/library/keychains/",
        "/system/library/openssl/",
        "/windows/system32/catroot/",
        "/windows/system32/catroot2/",
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
                "/system/library/keychains/",
                "ca-certificates.crt",
                "ca-bundle.crt",
            ]):
                return True
    except Exception:
        pass

    # 6. Check if file is located in a known system CA path across Linux, Windows, macOS, or mounted sysroots
    in_system_ca_path = any(
        sys_token in p_lower for sys_token in [
            "/etc/ssl/certs",
            "/etc/pki/tls/certs",
            "/private/etc/ssl/certs",
            "/common files/ssl",
            "/openssl-win64/certs",
            "/openssl-win32/certs",
            "/programdata/openssl",
            "/programdata/ssl",
            "/opt/homebrew/share/ca-certificates",
        ]
    )

    if not in_system_ca_path:
        return False

    # In /usr/local/share/ca-certificates or /opt/homebrew/share/ca-certificates: ALWAYS user/admin custom CA
    if "/usr/local/" in p_lower or "/opt/homebrew/share/" in p_lower:
        return False

    # In system directories: non-symlink, non-bundle files are typically user/application certs,
    # UNLESS their subject or issuer explicitly identifies them as a known public vendor CA.
    if not file_path.is_symlink() and name_lower not in OS_BUNDLE_FILENAMES:
        if cert:
            try:
                subj = cert.subject.rfc4514_string().lower()
                issuer = cert.issuer.rfc4514_string().lower()
                if any(pub in subj or pub in issuer for pub in KNOWN_PUBLIC_CA_TOKENS) and not any(
                    k in subj for k in ["nexis", "ecdat", "internal", "local", "corp", "private", "test", "dev", "custom", "company", "enterprise"]
                ):
                    return True
            except Exception:
                pass
        elif any(pub_token in name_lower for pub_token in KNOWN_PUBLIC_CA_TOKENS) and not any(
            k in name_lower for k in ["nexis", "ecdat", "internal", "local", "corp", "private", "test", "dev", "custom", "company", "enterprise"]
        ):
            return True
        return False

    # 7. For symlinks, bundles, or system store files, inspect certificate properties if available
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
            if any(internal_kw in subj for internal_kw in ["nexis", "ecdat", "internal", "local", "corp", "private", "test", "dev", "myca", "custom", "company", "enterprise"]):
                return False
            issuer = cert.issuer.rfc4514_string().lower()
            if any(pub_token in subj or pub_token in issuer or pub_token in name_lower for pub_token in KNOWN_PUBLIC_CA_TOKENS):
                return True
        except Exception:
            pass

    # If without cert object yet, check filename tokens
    if any(pub_token in name_lower for pub_token in KNOWN_PUBLIC_CA_TOKENS):
        return True

    return False


def get_os_trust_store_label(target_dir: Optional[Path] = None) -> str:
    """
    Returns an appropriate human-readable description of the OS root CA trust store
    based on the current operating system, container environment, or target filesystem.
    """
    if target_dir:
        t_str = str(target_dir).replace("\\", "/").lower()
        if "/proc/" in t_str or "/tmp/spectra_containers/" in t_str:
            return "/etc/ssl/certs, ca-certificates"
        if any(w_cand in t_str for w_cand in ["c:/", "d:/", "e:/", "program files", "windows"]):
            return "Windows Root Store, OpenSSL certs"
        if any(m_cand in t_str for m_cand in ["/library/", "/system/", "/volumes/"]):
            return "macOS Keychain, /etc/ssl/certs"

    # Host OS detection
    sys_name = platform.system()
    if sys_name == "Windows":
        return "Windows Root Store, OpenSSL certs"
    elif sys_name == "Darwin":
        return "macOS Keychain, /etc/ssl/certs"
    else:
        return "/etc/ssl/certs, /etc/pki, ca-certificates"



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


def format_display_path(
    file_path: Any,
    target_dir: Optional[Any] = None,
) -> str:
    """
    Formats a file path for display in telemetry progress tables, reports, and CBOM.
    - Preserves container-native paths (e.g., /etc/ssl/..., /opt/nexis/...) by stripping
      container mount prefixes (/scan/proc/<pid>/root, /proc/<pid>/root, /tmp/spectra_containers/<name>).
    - If a path is inside target_dir, retains the user-specified target directory prefix
      (e.g., /opt/nexis/keys/gateway-key.pem instead of keys/gateway-key.pem).
    """
    if not file_path:
        return ""

    p_str = str(file_path).replace("\\", "/")

    container_mount_pattern = re.compile(
        r"^((?:/(?:scan|host))?/proc/\d+/root|/tmp/spectra_containers/[^/]+)(/.*)?$"
    )
    m = container_mount_pattern.match(p_str)
    if m:
        sub = m.group(2) or "/"
        return sub if sub.startswith("/") else f"/{sub}"

    if target_dir:
        t_str = str(target_dir).replace("\\", "/")
        m_t = container_mount_pattern.match(t_str)
        user_c_dir = (m_t.group(2) or "/") if m_t else None

        # If file_path is already a relative subpath (e.g. 'keys/gateway-key.pem')
        if not p_str.startswith("/") and not (len(p_str) > 1 and p_str[1] == ":"):
            if user_c_dir:
                base = user_c_dir.rstrip("/")
                return f"{base}/{p_str}" if base else f"/{p_str}"
            else:
                base = t_str.rstrip("/")
                if base and base != ".":
                    return f"{base}/{p_str}"
                return p_str

        # If file_path is under target_dir on host
        try:
            p_obj = Path(p_str)
            t_obj = Path(t_str)
            rel = p_obj.relative_to(t_obj)
            rel_str = str(rel).replace("\\", "/")
            if user_c_dir:
                base = user_c_dir.rstrip("/")
                return f"{base}/{rel_str}" if base else f"/{rel_str}"
            else:
                base = t_str.rstrip("/")
                if base and base != ".":
                    return f"{base}/{rel_str}"
                return rel_str
        except Exception:
            pass

    return p_str

