"""
spectra.utils.docker_client
===========================
Lightweight, zero-dependency Docker Engine API client using Unix Domain Sockets (/var/run/docker.sock).
Enables Spectra to discover, inspect, and extract codebases directly from running Docker containers
without requiring host volume mounts or external Docker SDK dependencies.
"""

import http.client
import io
import json
import logging
import os
import shutil
import socket
import tarfile
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("spectra.docker_client")


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection subclass that communicates over a Unix domain socket."""

    def __init__(self, socket_path: str = "/var/run/docker.sock", timeout: int = 180):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class DockerContainerClient:
    """Client for inspecting and extracting files from running Docker containers via Docker Socket."""

    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path

    def is_available(self) -> bool:
        """Check if Docker socket exists and is accessible."""
        return os.path.exists(self.socket_path) and os.access(self.socket_path, os.R_OK | os.W_OK)

    def _request(self, method: str, endpoint: str) -> Tuple[int, bytes, Dict[str, str]]:
        """Perform a raw HTTP request to the Docker daemon over unix socket."""
        conn = UnixSocketHTTPConnection(self.socket_path)
        try:
            conn.request(method, endpoint, headers={"Host": "localhost"})
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            data = resp.read()
            return resp.status, data, headers
        finally:
            conn.close()

    def list_containers(self, all: bool = False) -> List[Dict[str, Any]]:
        """List running containers from Docker daemon."""
        endpoint = f"/v1.43/containers/json?all={'1' if all else '0'}"
        status, data, _ = self._request("GET", endpoint)
        if status != 200:
            raise RuntimeError(f"Docker API error ({status}): {data.decode('utf-8', errors='replace')}")
        return json.loads(data.decode("utf-8"))

    def get_container_info(self, container_id_or_name: str) -> Dict[str, Any]:
        """Fetch container JSON metadata from Docker Engine API."""
        safe_name = container_id_or_name.strip()
        endpoint = f"/v1.43/containers/{safe_name}/json"
        status, data, _ = self._request("GET", endpoint)
        if status == 404:
            raise ValueError(f"Docker container '{container_id_or_name}' not found on host daemon.")
        if status != 200:
            raise RuntimeError(f"Docker API error ({status}): {data.decode('utf-8', errors='replace')}")
        return json.loads(data.decode("utf-8"))

    def get_container_ip(self, container_id_or_name: str) -> Optional[str]:
        """Extract primary IP address of the container."""
        try:
            info = self.get_container_info(container_id_or_name)
            net_settings = info.get("NetworkSettings", {})
            ip = net_settings.get("IPAddress")
            if ip and ip.strip():
                return ip.strip()
            networks = net_settings.get("Networks", {})
            for net_name, net_data in networks.items():
                net_ip = net_data.get("IPAddress")
                if net_ip and net_ip.strip():
                    return net_ip.strip()
        except Exception:
            pass
        return None

    def get_container_network_ports(self, container_id_or_name: str) -> Dict[str, Any]:
        """Extract exposed ports and host port bindings."""
        result = {
            "ip": None,
            "status": "unknown",
            "is_running": False,
            "exposed_ports": [],
            "port_bindings": {},  # container_port -> list of host_ports
        }
        try:
            info = self.get_container_info(container_id_or_name)
            result["status"] = info.get("State", {}).get("Status", "unknown")
            result["is_running"] = info.get("State", {}).get("Running", False)
            result["ip"] = self.get_container_ip(container_id_or_name)
            exposed = info.get("Config", {}).get("ExposedPorts", {}) or {}
            for ep_key in exposed.keys():
                port_str = ep_key.split("/")[0]
                if port_str.isdigit():
                    result["exposed_ports"].append(int(port_str))
            
            bindings = info.get("HostConfig", {}).get("PortBindings", {}) or {}
            if not bindings:
                bindings = info.get("NetworkSettings", {}).get("Ports", {}) or {}
            
            for cp_key, host_list in bindings.items():
                cp_str = cp_key.split("/")[0]
                if cp_str.isdigit() and host_list:
                    cp_int = int(cp_str)
                    host_ports = []
                    for h in host_list:
                        hp = h.get("HostPort")
                        if hp and str(hp).isdigit():
                            host_ports.append(int(hp))
                    if host_ports:
                        result["port_bindings"][cp_int] = host_ports
        except Exception:
            pass
        return result

    def extract_container_path(
        self,
        container_id_or_name: str,
        container_path: str,
        dest_dir: Optional[Path] = None,
        reset_dest: bool = True,
    ) -> Path:
        """
        Extracts a path from inside a running container using Docker Archive API.
        Returns the local Path containing the extracted files.
        """
        safe_name = container_id_or_name.strip()
        encoded_path = urllib.parse.quote(container_path)
        endpoint = f"/v1.43/containers/{safe_name}/archive?path={encoded_path}"

        conn = UnixSocketHTTPConnection(self.socket_path)
        try:
            conn.request("GET", endpoint, headers={"Host": "localhost"})
            resp = conn.getresponse()
            if resp.status == 404:
                raise FileNotFoundError(
                    f"Path '{container_path}' not found inside container '{container_id_or_name}'."
                )
            if resp.status != 200:
                err_msg = resp.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Docker archive error ({resp.status}): {err_msg}")

            clean_name = safe_name.replace("/", "_").strip("_")
            if dest_dir is None:
                dest_dir = Path("/tmp/spectra_containers") / clean_name

            # Reset destination folder if requested
            if reset_dest and dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Read tar stream and unpack
            tar_bytes = resp.read()
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
                for member in tar.getmembers():
                    member.name = member.name.lstrip("/")
                try:
                    tar.extractall(path=dest_dir, filter="data")
                except TypeError:
                    tar.extractall(path=dest_dir)

            base_name = Path(container_path.rstrip("/")).name
            extracted_sub = dest_dir / base_name
            if extracted_sub.is_dir():
                return extracted_sub
            return dest_dir
        finally:
            conn.close()

    def resolve_container_perimeter(
        self,
        container_id_or_name: str,
        container_path: Optional[str] = None,
    ) -> Tuple[Path, Dict[str, Any]]:
        """
        Resolves the filesystem path for the target container.
        1. Fast-path (--pid=host): If host PID tree (/proc/<pid>/root) is accessible,
           binds directly to the whole container filesystem with zero copy and instant access.
        2. Fallback: Streams the container filesystem archive via Docker Archive API.
        """
        info = self.get_container_info(container_id_or_name)
        pid = info.get("State", {}).get("Pid", 0)

        target_subpath = (container_path or "/").strip()
        if not target_subpath:
            target_subpath = "/"

        # 1. Fast-path: Check if direct host proc filesystem is accessible via --pid=host or /scan/proc
        if pid > 0:
            for proc_cand in [
                Path(f"/proc/{pid}/root"),
                Path(f"/scan/proc/{pid}/root"),
                Path(f"/host/proc/{pid}/root"),
            ]:
                if proc_cand.exists() and os.access(proc_cand, os.R_OK):
                    logger.info(f"Direct host proc perimeter active at {proc_cand} (PID: {pid})")
                    if target_subpath in ("", "/"):
                        return proc_cand, info
                    sub_target = proc_cand / target_subpath.lstrip("/")
                    if sub_target.exists():
                        return sub_target, info
                    return proc_cand, info

        # 2. Archive API streaming fallback (when running without direct proc access)
        clean_name = container_id_or_name.replace("/", "_").strip("_")
        staging_root = Path("/tmp/spectra_containers") / clean_name

        if staging_root.exists():
            shutil.rmtree(staging_root, ignore_errors=True)
        staging_root.mkdir(parents=True, exist_ok=True)

        logger.info(f"Extracting container archive for {container_id_or_name}:{target_subpath}")
        extracted_path = self.extract_container_path(
            container_id_or_name, target_subpath, dest_dir=staging_root, reset_dest=False
        )

        # Also extract container's system configs, certificates, and keys into proper root hierarchy
        for sys_path in ["/etc/ssl", "/etc/nginx", "/usr/local/share/ca-certificates", "/root", "/home"]:
            try:
                rel_path = sys_path.lstrip("/")
                target_dest = staging_root / rel_path
                target_dest.parent.mkdir(parents=True, exist_ok=True)
                self.extract_container_path(
                    container_id_or_name, sys_path, dest_dir=target_dest.parent, reset_dest=False
                )
            except Exception:
                pass

        return extracted_path, info
