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
from typing import List, Optional, Set


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


def get_certificate_system_paths(target_dir: Optional[Path] = None) -> List[Path]:
    """
    Returns all existing directories likely to contain system SSL/TLS certificates,
    private keys, and CA trust stores across target_dir and all discovered roots.
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
        "etc/pki/ca-trust",
        "etc/ca-certificates",
        "usr/local/share/ca-certificates",
        "usr/share/ca-certificates",
        "var/ssl",
        "Program Files/OpenSSL-Win64",
        "Program Files/Common Files/SSL",
    ]

    for root in discover_root_mounts(target_dir):
        for sub in subdirs:
            _add_path(root / sub)

    return candidate_paths


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
