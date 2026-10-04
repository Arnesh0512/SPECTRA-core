"""
spectra.scanners.artifacts.runtime_scanner
===============================================
Dynamic runtime shared library inspector with Docker-aware process isolation.
Audits active loaded dynamic link libraries (.dll, .so, .dylib) mapped into 
process memory for Container C1 or the local host machine, ignoring Container C2.
"""

import http.client
import json
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import psutil
import yaml


class UnixHTTPConnection(http.client.HTTPConnection):
    """Helper class to communicate with Docker daemon over Unix socket without external SDKs."""
    def __init__(self, unix_socket_path: str = "/var/run/docker.sock"):
        super().__init__("localhost")
        self.unix_socket_path = unix_socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.unix_socket_path)


@dataclass
class RuntimeFinding:
    """Represents runtime shared library or DLL evidence from process memory maps."""
    source_domain: str = "artifacts"
    artifact_type: str = "runtime_environment"
    file_path: str = ""
    finding_category: str = "loaded_shared_library"
    details: str = ""
    algorithm: str = "Native-Binary"
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "finding_category": self.finding_category,
            "details": self.details,
            "algorithm": self.algorithm,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class RuntimeScanner:
    """Intelligently inspects process memory maps for shared libraries / DLLs (.so, .dll, .dylib) 
    targeting Container C1, local machine runtime, while strictly ignoring Container C2."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "runtime_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        self.target_extensions = tuple(self.rules.get("target_shared_object_extensions", [".so", ".dll", ".dylib"]))

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _is_shared_library(self, path: str) -> bool:
        """Determines if a mapped file path represents a dynamic shared library or DLL."""
        if not path or not path.strip():
            return False
        low = path.lower()
        # Support versioned Linux shared libraries (.so, .so.1, .so.3, .so.1.1.0)
        # as well as Windows DLLs (.dll) and macOS dylibs (.dylib)
        return bool(re.search(r"\.(so(\.\d+)*|dll|dylib)$", low))

    def _detect_runtime_algorithm(self, path: str) -> Dict[str, Any]:
        """Classifies cryptographic relevance and algorithm characteristics of runtime libraries."""
        name_low = Path(path).name.lower()
        full_low = path.lower()

        # Post-Quantum Cryptography libraries
        if any(k in name_low for k in ["oqs", "pqcrypto", "dilithium", "kyber", "sphincs", "falcon"]):
            return {
                "algorithm": "ML-KEM / ML-DSA (Post-Quantum Safe)",
                "quantum_safe": True,
                "shor_vulnerable": False,
                "category": "post_quantum_runtime",
            }

        # OpenSSL / Libcrypto / Libssl
        if "libcrypto" in name_low:
            return {
                "algorithm": "OpenSSL-libcrypto (EVP / Ciphers)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "cryptographic_library",
            }
        if "libssl" in name_low:
            return {
                "algorithm": "OpenSSL-libssl (TLS / Handshake)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "tls_library",
            }

        # libcrypt (POSIX hashing/crypt)
        if "libcrypt." in name_low or "libcrypt-" in name_low or name_low.startswith("libcrypt"):
            return {
                "algorithm": "libcrypt (POSIX Hashing / Crypt)",
                "quantum_safe": False,
                "shor_vulnerable": False,
                "category": "hash_library",
            }

        # Python Cryptography & Rust HAZMAT bindings
        if "cryptography" in full_low and "_rust" in name_low:
            return {
                "algorithm": "PyCA-Cryptography-Rust (AES / RSA / ECC)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "cryptographic_library",
            }
        if "_bcrypt" in name_low or "bcrypt." in name_low or name_low.startswith("bcrypt"):
            return {
                "algorithm": "bcrypt (Key-Derivation / Password-Hash)",
                "quantum_safe": False,
                "shor_vulnerable": False,
                "category": "kdf_library",
            }
        if "_hashlib" in name_low:
            return {
                "algorithm": "Python-Hashlib (SHA-2 / OpenSSL-EVP)",
                "quantum_safe": True,
                "shor_vulnerable": False,
                "category": "hash_library",
            }
        if "_ssl" in name_low:
            return {
                "algorithm": "Python-SSL (TLS-Engine)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "tls_library",
            }
        if "libssh" in name_low:
            return {
                "algorithm": "libssh (SSH2-Transport-Crypto)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "ssh_library",
            }
        if "gnutls" in name_low:
            return {
                "algorithm": "GnuTLS (Crypto / TLS Engine)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "tls_library",
            }
        if "softhsm" in name_low or "pkcs11" in name_low:
            return {
                "algorithm": "SoftHSM2-PKCS11 (Cryptographic Token)",
                "quantum_safe": False,
                "shor_vulnerable": True,
                "category": "hsm_runtime",
            }

        return {
            "algorithm": "Native-Binary",
            "quantum_safe": False,
            "shor_vulnerable": True,
            "category": "loaded_shared_library",
        }

    def _get_target_pids(
        self,
        target_dir: Optional[Path] = None,
        container_name: Optional[str] = None
    ) -> Optional[Set[int]]:
        """Resolves target PIDs using Docker socket inspection or /proc perimeter matching.
        Returns a Set of PIDs belonging exclusively to target container C1, or None for Host mode."""
        root_pid = 0
        docker_socket_path = "/var/run/docker.sock"

        # 1. Direct Docker inspect by container name/ID if socket exists
        if container_name and os.path.exists(docker_socket_path):
            try:
                conn = UnixHTTPConnection(docker_socket_path)
                conn.request("GET", f"/containers/{container_name}/json")
                resp = conn.getresponse()
                if resp.status == 200:
                    c_info = json.loads(resp.read().decode())
                    root_pid = c_info.get("State", {}).get("Pid", 0)
            except Exception:
                pass

        # 2. Extract PID from container perimeter target path (e.g. /proc/113932/root/...)
        if root_pid <= 0 and target_dir:
            m = re.match(r"^/proc/(\d+)/root", str(target_dir))
            if m:
                try:
                    root_pid = int(m.group(1))
                except ValueError:
                    pass

        # 3. Fallback: Search all running containers via Docker socket
        if root_pid <= 0 and os.path.exists(docker_socket_path):
            try:
                conn = UnixHTTPConnection(docker_socket_path)
                conn.request("GET", "/containers/json")
                resp = conn.getresponse()
                if resp.status == 200:
                    containers = json.loads(resp.read().decode())
                    target_str = str(target_dir.resolve()).lower() if target_dir else ""

                    for container in containers:
                        c_id = container.get("Id", "")
                        # Check name match
                        names = [n.lstrip("/") for n in container.get("Names", [])]
                        if container_name and (container_name in names or container_name == c_id):
                            inspect_conn = UnixHTTPConnection(docker_socket_path)
                            inspect_conn.request("GET", f"/containers/{c_id}/json")
                            inspect_resp = inspect_conn.getresponse()
                            if inspect_resp.status == 200:
                                c_info = json.loads(inspect_resp.read().decode())
                                root_pid = c_info.get("State", {}).get("Pid", 0)
                                if root_pid > 0:
                                    break

                        # Check mount match
                        if root_pid <= 0 and target_str:
                            inspect_conn = UnixHTTPConnection(docker_socket_path)
                            inspect_conn.request("GET", f"/containers/{c_id}/json")
                            inspect_resp = inspect_conn.getresponse()
                            if inspect_resp.status == 200:
                                c_info = json.loads(inspect_resp.read().decode())
                                for mount in c_info.get("Mounts", []):
                                    destination = mount.get("Destination", "").lower()
                                    source = mount.get("Source", "").lower()
                                    if destination and (destination in target_str or target_str in destination):
                                        root_pid = c_info.get("State", {}).get("Pid", 0)
                                        break
                                    if source and (source in target_str or target_str in source):
                                        root_pid = c_info.get("State", {}).get("Pid", 0)
                                        break
                        if root_pid > 0:
                            break
            except Exception:
                pass

        # If a container root PID was resolved, expand to all child processes
        if root_pid > 0:
            valid_pids = {root_pid}
            try:
                parent = psutil.Process(root_pid)
                for child in parent.children(recursive=True):
                    valid_pids.add(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            return valid_pids

        return None

    def _get_process_maps(self, proc: psutil.Process, pid: int) -> List[str]:
        """Extracts mapped file paths using psutil and direct Linux /proc/<pid>/maps fallback."""
        paths = []
        try:
            mmap_func = getattr(proc, "memory_maps", None)
            if mmap_func:
                for m in mmap_func():
                    p = getattr(m, "path", "")
                    if p:
                        paths.append(p)
                if paths:
                    return paths
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return []
        except Exception:
            pass

        # Linux direct /proc/<pid>/maps fallback for processes with restricted permissions
        maps_file = Path(f"/proc/{pid}/maps")
        if maps_file.exists():
            try:
                with open(maps_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            p = parts[5]
                            if p.startswith("/"):
                                paths.append(p)
            except Exception:
                pass

        return paths

    def scan(
        self,
        target_dir: Optional[Path] = None,
        container_name: Optional[str] = None
    ) -> List[RuntimeFinding]:
        """Collects active loaded shared libraries and DLLs from memory maps based on target isolation."""
        findings: List[RuntimeFinding] = []
        artifacts: Dict[str, Dict[str, Any]] = {}

        # Determine target process scope (Container C1 PIDs vs Host PIDs minus C2)
        target_pids = self._get_target_pids(target_dir, container_name)
        current_c2_pid = os.getpid()
        c2_process_tree = set()
        try:
            c2_proc = psutil.Process(current_c2_pid)
            c2_process_tree.add(c2_proc.pid)
            for child in c2_proc.children(recursive=True):
                c2_process_tree.add(child.pid)
        except Exception:
            pass

        # Process candidates to audit
        candidate_pids = list(target_pids) if target_pids is not None else []
        if not candidate_pids:
            try:
                candidate_pids = [p.pid for p in psutil.process_iter(["pid"])]
            except Exception:
                candidate_pids = []

        for pid in candidate_pids:
            # Rule 1: If scanning C1, strictly look only at C1's PIDs
            if target_pids is not None and pid not in target_pids:
                continue

            # Rule 2: If scanning local/host, explicitly ignore C2 container processes
            if target_pids is None and pid in c2_process_tree:
                continue

            try:
                proc = psutil.Process(pid)
                pname = proc.name()
                pid_str = str(pid)
                mapped_paths = self._get_process_maps(proc, pid)

                for path in mapped_paths:
                    if self._is_shared_library(path):
                        lib_item = artifacts.setdefault(path, {
                            "path": path,
                            "pids": [],
                            "proc_names": [],
                        })
                        if pid_str not in lib_item["pids"]:
                            lib_item["pids"].append(pid_str)
                        if pname and pname not in lib_item["proc_names"]:
                            lib_item["proc_names"].append(pname)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        for path, info in artifacts.items():
            meta_algo = self._detect_runtime_algorithm(path)
            procs_str = f" ({', '.join(info['proc_names'][:3])})" if info["proc_names"] else ""
            pids_str = f"PIDs: {', '.join(info['pids'][:5])}"

            findings.append(RuntimeFinding(
                source_domain="artifacts",
                artifact_type="runtime_environment",
                file_path=path,
                finding_category=meta_algo["category"],
                details=f"Active runtime shared library: {Path(path).name} in {pids_str}{procs_str}",
                algorithm=meta_algo["algorithm"],
                quantum_safe=meta_algo["quantum_safe"],
                shor_vulnerable=meta_algo["shor_vulnerable"],
                security_findings=[],
                raw_metadata={
                    "role": "shared_library",
                    "pids": info["pids"],
                    "processes": info["proc_names"],
                    "category": meta_algo["category"],
                }
            ))

        return findings