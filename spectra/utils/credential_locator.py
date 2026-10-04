r"""
spectra.utils.credential_locator
================================
Dynamic multi-mode host and container credential discovery engine.

Implements three distinct operational modes:

MODE 1: Running on local machine directly (`python -m spectra.cli scan`)
- Platform: Windows, macOS, or Linux.
- Step i: Detect current user who executed it (via USER/USERNAME/getpass).
- Step ii: Inspect their home directory (~, C:\Users\<user>, /home/<user>, /Users/<user>)
  for .aws, .azure, GCP (AppData/Roaming/gcloud or ~/.config/gcloud), and .ssh.

MODE 2 - CASE 1: Running as Spectra container with mounted host filesystem (no --container flag)
- Step 1: Using the provided target_dir (e.g. /scan/... or /abc/...), discover which host mount
  we are working within (from /proc/self/mountinfo or path hierarchy).
- Step 2: Determine host user:
  a. Priority A: Explicitly supplied via `docker run -e HOST_USER=$USER`.
  b. Priority B: Extracted from target_dir path components (e.g. /scan/home/ArneshArchWSL/...).
  c. Priority C: Auto-detected via /etc/wsl.conf ([user] default=...), /etc/passwd (UID 1000),
     or most recently active user history (.bash_history, NTUSER.DAT).
- Step 3: Search that user's home directory on the mounted host filesystem for .aws, .azure, GCP, .ssh.

MODE 2 - CASE 2: Running against a target container (--container flag provided)
- Strictly search ONLY within the target container's own filesystem (via Docker Engine API or
  the extracted container staging directory /tmp/spectra_containers/<name>).
- Look for:
  - AWS: .aws/credentials, .aws/config
  - Azure: .azure/
  - SSH: .ssh/
  - GCP: .config/gcloud/ or application_default_credentials.json
- Strictly IGNORE host mounted directories (/scan, /host, etc.) so credentials come exclusively
  from the target container under audit!
"""

from dataclasses import dataclass, field
import getpass
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


def is_running_in_container() -> bool:
    """Returns True if Spectra is executing inside a Docker/OCI container, False on native host."""
    if sys.platform == "win32":
        return False
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    for cg in [Path("/proc/self/cgroup"), Path("/proc/1/cgroup")]:
        if cg.exists():
            try:
                content = cg.read_text()
                if any(m in content for m in ["docker", "containerd", "kubepods", "lxc", "overlay"]):
                    return True
            except Exception:
                pass
    p1 = Path("/proc/1/comm")
    if p1.exists():
        try:
            comm = p1.read_text().strip()
            if comm not in ["systemd", "init"]:
                return True
        except Exception:
            pass
    return False


@dataclass
class DiscoveredCredentials:
    """Encapsulates discovered cloud and cryptographic credentials."""
    # AWS
    aws_credentials_file: Optional[Path] = None
    aws_config_file: Optional[Path] = None
    
    # Azure
    azure_config_dir: Optional[Path] = None
    
    # GCP
    gcp_credentials_file: Optional[Path] = None
    gcp_config_dir: Optional[Path] = None
    
    # SSH
    ssh_dir: Optional[Path] = None
    ssh_keys: List[Path] = field(default_factory=list)
    
    # Metadata
    detected_user: Optional[str] = None
    detected_os: Optional[str] = None
    root_mount: Optional[Path] = None
    mode: str = "unknown"

    @property
    def has_aws(self) -> bool:
        return self.aws_credentials_file is not None and self.aws_credentials_file.exists()

    @property
    def has_azure(self) -> bool:
        return self.azure_config_dir is not None and self.azure_config_dir.exists()

    @property
    def has_gcp(self) -> bool:
        return (
            (self.gcp_credentials_file is not None and self.gcp_credentials_file.exists())
            or (self.gcp_config_dir is not None and self.gcp_config_dir.exists())
        )

    @property
    def has_ssh(self) -> bool:
        return bool(self.ssh_keys) or (self.ssh_dir is not None and self.ssh_dir.exists())


class CredentialLocator:
    """Discovers host and container credentials across the 3 operational modes."""

    SYSTEM_USERS_IGNORE: Set[str] = {
        "all users", "default", "default user", "public", "desktop.ini",
        "shared", "guest", "lost+found"
    }

    def __init__(self, target_dir: Optional[Path] = None, container_target: Optional[str] = None):
        if target_dir:
            self.target_dir = Path(target_dir) if "/proc/" in str(target_dir) else Path(target_dir).resolve()
        else:
            self.target_dir = None
        self.container_target = container_target.strip() if container_target else None

    # =========================================================================
    # MODE 1: Local Machine Execution (python -m spectra.cli scan)
    # =========================================================================
    def _discover_mode1_local(self) -> DiscoveredCredentials:
        """
        Mode 1: Running directly on local machine (Windows, Mac, Linux).
        Step i: Find out current user who executed it.
        Step ii: Go to user home to find AWS, Azure, GCP, and SSH.
        """
        home = Path.home()
        os_type = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
        user = os.environ.get("USERNAME") or os.environ.get("USER") or os.environ.get("LOGNAME") or getpass.getuser()

        creds = self._inspect_user_credentials(home, os_type)
        creds.detected_user = user
        creds.detected_os = os_type
        creds.root_mount = Path(home.anchor) if home.anchor else Path("/")
        creds.mode = "mode1_local"
        return creds

    # =========================================================================
    # MODE 2 - CASE 1: Spectra Container - Mounted Host Filesystem (no --container)
    # =========================================================================
    def _resolve_active_mount_for_target(self, target_dir: Optional[Path]) -> Optional[Path]:
        """Step 1: Using target directory given, find out which mount we are currently working on."""
        if not target_dir:
            return None

        # 1. Inspect container mount table (/proc/self/mountinfo)
        mountinfo = Path("/proc/self/mountinfo")
        if mountinfo.exists():
            try:
                candidate_mounts = []
                for line in mountinfo.read_text().splitlines():
                    parts = line.split()
                    if len(parts) >= 5:
                        mp = Path(parts[4])
                        if mp != Path("/") and mp.exists():
                            candidate_mounts.append(mp)
                # Sort by length descending (longest prefix matching)
                candidate_mounts.sort(key=lambda p: len(p.parts), reverse=True)
                for mp in candidate_mounts:
                    try:
                        target_dir.relative_to(mp)
                        return mp
                    except Exception:
                        pass
            except Exception:
                pass

        # 2. Heuristic: Check path components (e.g. /scan/home/... -> /scan, /abc/xyz -> /abc)
        if len(target_dir.parts) >= 2:
            top_dir = Path("/" + target_dir.parts[1])
            if top_dir.exists() and top_dir.is_dir():
                return top_dir

        return None

    def _discover_mode2_case1_mounted_host(self) -> DiscoveredCredentials:
        """
        Mode 2 Case 1: Running in Spectra container with mounted host filesystem.
        Step 1: Identify active mount from target directory (e.g. /scan or /abc).
        Step 2: Check HOST_USER env var, target directory user, or auto-detect.
        Step 3: Find AWS, Azure, GCP, and SSH in that user's home on the mounted filesystem.
        """
        creds = DiscoveredCredentials()
        creds.mode = "mode2_case1_mounted_host"

        # Step 1: Find mount root from target directory
        active_mount = self._resolve_active_mount_for_target(self.target_dir)
        if not active_mount or not active_mount.exists():
            for common in [Path("/scan"), Path("/host"), Path("/target")]:
                if common.exists() and common.is_dir():
                    active_mount = common
                    break
        if not active_mount or not active_mount.exists():
            active_mount = Path("/")

        creds.root_mount = active_mount
        os_type, user_list = self.detect_os_and_users(active_mount)
        user_dict = {name.lower(): (name, path) for name, path in user_list if name != "root"}

        selected_user_tuple: Optional[Tuple[str, Path]] = None

        # Step 2: User resolution
        # Priority A: User explicitly told which user is current via HOST_USER=$USER
        explicit_user = os.environ.get("HOST_USER") or os.environ.get("WSL_USER") or os.environ.get("SUDO_USER")
        if explicit_user and explicit_user.lower() in user_dict:
            selected_user_tuple = user_dict[explicit_user.lower()]

        # Priority B: Extract username from target directory given by user
        if not selected_user_tuple and self.target_dir:
            selected_user_tuple = self.extract_user_from_target(user_list)

        # Priority C: Auto-detect user (wsl.conf, passwd UID 1000, active history)
        if not selected_user_tuple:
            selected_user_tuple = self.detect_default_user_from_host(active_mount, user_list)

        # Step 3: Look for credentials in the selected user's home
        if selected_user_tuple:
            u_name, u_path = selected_user_tuple
            user_creds = self._inspect_user_credentials(u_path, os_type)
            user_creds.root_mount = active_mount
            self._merge_credentials(creds, user_creds)

        # Search remaining users if any cloud credentials are not yet discovered
        for u_name, u_path in user_list:
            if not (creds.has_aws and creds.has_azure and creds.has_gcp):
                fallback_creds = self._inspect_user_credentials(u_path, os_type)
                self._merge_credentials(creds, fallback_creds)

        return creds

    # =========================================================================
    # MODE 2 - CASE 2: Scanning another container (--container flag passed)
    # =========================================================================
    def _discover_mode2_case2_target_container(self) -> DiscoveredCredentials:
        """
        Mode 2 Case 2: Scanning another container (--container flag provided).
        Only step: Find folders named .aws, .azure, .ssh, .config/gcloud strictly inside
        the target container (extracted staging perimeter).
        NEVER searches host mounted directories (/scan, /host, etc.).
        """
        creds = DiscoveredCredentials()
        creds.mode = "mode2_case2_target_container"
        creds.detected_os = "container_target"

        container_roots: List[Path] = []

        # 1. Target directory from container extraction (e.g. /tmp/spectra_containers/<name>)
        if self.target_dir and self.target_dir.exists():
            parts = list(self.target_dir.parts)
            if "spectra_containers" in parts:
                idx = parts.index("spectra_containers")
                if len(parts) > idx + 1:
                    container_roots.append(Path(*parts[:idx + 2]))
            container_roots.append(self.target_dir)

        # 2. Check /tmp/spectra_containers directly
        staging = Path("/tmp/spectra_containers")
        if staging.exists():
            if self.container_target:
                safe_name = self.container_target.replace("/", "_").strip("_")
                named_dir = staging / safe_name
                if named_dir.exists():
                    container_roots.append(named_dir)
            try:
                for sub in staging.iterdir():
                    if sub.is_dir() and sub not in container_roots:
                        container_roots.append(sub)
            except Exception:
                pass

        # 3. Proc container root if --pid=host
        if self.target_dir and str(self.target_dir).startswith("/proc/"):
            container_roots.append(self.target_dir)
            try:
                parts = list(self.target_dir.parts)
                if len(parts) >= 4 and parts[1] == "proc" and parts[3] == "root":
                    c_pid = parts[2]
                    c_proc_root = Path("/proc") / c_pid / "root"
                    container_roots.append(c_proc_root)
                    container_roots.append(c_proc_root / "root")

                    # Inspect live container process environment variables
                    env_file = Path("/proc") / c_pid / "environ"
                    if env_file.exists():
                        try:
                            raw = env_file.read_bytes()
                            for item in raw.split(b"\x00"):
                                if b"=" in item:
                                    k, v = item.decode("utf-8", errors="ignore").split("=", 1)
                                    k = k.strip()
                                    v = v.strip()
                                    if k in (
                                        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID",
                                        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "AWS_REGION",
                                        "GOOGLE_APPLICATION_CREDENTIALS"
                                    ) and v:
                                        os.environ[k] = v
                                        if k.startswith("AZURE_") and not creds.azure_config_dir:
                                            creds.azure_config_dir = env_file
                        except Exception:
                            pass
            except Exception:
                pass

        # Search STRICTLY inside target container directories (ignore /scan, /host)
        for c_root in container_roots:
            self._search_container_internal_credentials(c_root, creds)
            if creds.has_aws and creds.has_azure and creds.has_gcp and creds.has_ssh:
                break

        return creds

    def _search_container_internal_credentials(self, root: Path, creds: DiscoveredCredentials) -> None:
        """Searches exclusively inside the target container's extracted directories."""
        if not root.exists():
            return

        # Direct checks in standard container home locations (/root, /home/*)
        candidates = [root / "root"]
        home_dir = root / "home"
        if home_dir.exists() and home_dir.is_dir():
            try:
                for u in home_dir.iterdir():
                    if u.is_dir():
                        candidates.append(u)
            except Exception:
                pass
        candidates.append(root)  # also check container root/workdir

        for c in candidates:
            # Check for container environment files (.env)
            for env_name in [".env", ".env.local", ".env.production"]:
                env_file = c / env_name
                if env_file.is_file():
                    try:
                        for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                k = k.strip()
                                v = v.strip().strip("'\"")
                                if k in (
                                    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID",
                                    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "AWS_REGION",
                                    "GOOGLE_APPLICATION_CREDENTIALS"
                                ) and v:
                                    if not os.environ.get(k):
                                        os.environ[k] = v
                                    if k.startswith("AZURE_") and not creds.azure_config_dir:
                                        creds.azure_config_dir = env_file
                    except Exception:
                        pass

            # 1. AWS
            aws_dir = c / ".aws"
            if aws_dir.exists():
                if (aws_dir / "credentials").exists() and not creds.aws_credentials_file:
                    creds.aws_credentials_file = aws_dir / "credentials"
                if (aws_dir / "config").exists() and not creds.aws_config_file:
                    creds.aws_config_file = aws_dir / "config"

            # 2. Azure
            az_dir = c / ".azure"
            if az_dir.exists() and not creds.azure_config_dir:
                creds.azure_config_dir = az_dir

            # 3. GCP
            gcp_adc = c / ".config" / "gcloud" / "application_default_credentials.json"
            if gcp_adc.exists() and not creds.gcp_credentials_file:
                creds.gcp_credentials_file = gcp_adc
                creds.gcp_config_dir = gcp_adc.parent
            elif (c / ".config" / "gcloud").exists() and not creds.gcp_config_dir:
                creds.gcp_config_dir = c / ".config" / "gcloud"

            # 4. SSH
            ssh_dir = c / ".ssh"
            if ssh_dir.exists() and not creds.ssh_dir:
                creds.ssh_dir = ssh_dir
                try:
                    for k in ssh_dir.iterdir():
                        if k.is_file() and not k.name.endswith(".pub"):
                            creds.ssh_keys.append(k)
                except Exception:
                    pass

        # If any credentials are still missing, search recursively inside target container filesystem
        # (pruning virtual filesystems if inspecting a live container mount)
        if not (creds.has_aws and creds.has_azure and creds.has_gcp and creds.has_ssh):
            PRUNE_DIRS = {"proc", "sys", "dev", "run", ".git"}
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
                p = Path(dirpath)

                # 1. AWS folder
                if p.name == ".aws":
                    if (p / "credentials").exists() and not creds.aws_credentials_file:
                        creds.aws_credentials_file = p / "credentials"
                    if (p / "config").exists() and not creds.aws_config_file:
                        creds.aws_config_file = p / "config"

                # 2. Azure folder
                if p.name == ".azure" and not creds.azure_config_dir:
                    creds.azure_config_dir = p

                # 3. GCP folder (named "gcloud" or containing application_default_credentials.json)
                if p.name == "gcloud":
                    adc = p / "application_default_credentials.json"
                    if adc.exists() and not creds.gcp_credentials_file:
                        creds.gcp_credentials_file = adc
                        creds.gcp_config_dir = p
                    elif not creds.gcp_config_dir:
                        creds.gcp_config_dir = p

                # 4. SSH folder
                if p.name == ".ssh" and not creds.ssh_dir:
                    creds.ssh_dir = p
                    try:
                        for k in p.iterdir():
                            if k.is_file() and not k.name.endswith(".pub"):
                                creds.ssh_keys.append(k)
                    except Exception:
                        pass

                if creds.has_aws and creds.has_azure and creds.has_gcp and creds.has_ssh:
                    break

    # =========================================================================
    # Dispatcher
    # =========================================================================
    def discover(self) -> DiscoveredCredentials:
        """
        Executes credential discovery adhering strictly to the active mode:
        - Mode 2 Case 2: If container_target (--container) is supplied.
        - Mode 2 Case 1: If executing inside a container (without --container).
        - Mode 1: If executing natively on host machine.
        """
        # Case 2: Target container scanning
        if self.container_target:
            return self._discover_mode2_case2_target_container()

        # Case 1: Running in Spectra container with host mount
        if is_running_in_container():
            return self._discover_mode2_case1_mounted_host()

        # Mode 1: Running directly on local machine
        return self._discover_mode1_local()

    # =========================================================================
    # Shared Helper Methods
    # =========================================================================
    def detect_os_and_users(self, root: Path) -> Tuple[str, List[Tuple[str, Path]]]:
        user_list: List[Tuple[str, Path]] = []
        os_type = "unknown"

        win_users = root / "Users"
        if not win_users.exists() and (root / "users").exists():
            win_users = root / "users"

        is_windows = win_users.exists() and win_users.is_dir() and (
            (root / "Windows").exists() or (root / "Program Files").exists() or os.name == "nt"
        )
        is_macos = win_users.exists() and win_users.is_dir() and (
            (root / "Library").exists() or (root / "System").exists() or sys.platform == "darwin"
        )
        linux_home = root / "home"
        is_linux = linux_home.exists() and linux_home.is_dir()

        if is_macos:
            os_type = "macos"
            base_dir = win_users
        elif is_windows:
            os_type = "windows"
            base_dir = win_users
        elif is_linux:
            os_type = "linux"
            base_dir = linux_home
        elif (root / "etc").exists():
            os_type = "linux"
            base_dir = linux_home
        elif sys.platform == "win32":
            os_type = "windows"
            base_dir = Path("C:/Users")
        else:
            os_type = "linux"
            base_dir = Path("/home")

        if base_dir.exists() and base_dir.is_dir():
            try:
                for entry in base_dir.iterdir():
                    if entry.is_dir() and entry.name.lower() not in self.SYSTEM_USERS_IGNORE:
                        user_list.append((entry.name, entry))
            except Exception:
                pass

        root_home = root / "root"
        if root_home.exists() and root_home.is_dir():
            user_list.append(("root", root_home))

        return os_type, user_list

    def extract_user_from_target(self, user_list: List[Tuple[str, Path]]) -> Optional[Tuple[str, Path]]:
        if not self.target_dir:
            return None

        target_parts = [p.lower() for p in self.target_dir.parts]
        for u_name, u_path in user_list:
            try:
                self.target_dir.relative_to(u_path)
                return (u_name, u_path)
            except Exception:
                pass

        for u_name, u_path in user_list:
            if u_name.lower() in target_parts:
                return (u_name, u_path)

        return None

    def detect_default_user_from_host(self, root: Path, user_list: List[Tuple[str, Path]]) -> Optional[Tuple[str, Path]]:
        user_dict = {name.lower(): (name, path) for name, path in user_list if name != "root"}

        # 1. Environment variables
        for env_key in ["HOST_USER", "WSL_USER", "SUDO_USER", "DETECTED_USER", "ORIGINAL_USER"]:
            val = os.environ.get(env_key)
            if val and val.lower() in user_dict:
                return user_dict[val.lower()]

        # 2. WSL official default user: /etc/wsl.conf
        wsl_conf = root / "etc" / "wsl.conf"
        if wsl_conf.exists():
            try:
                import configparser
                cp = configparser.ConfigParser()
                cp.read(wsl_conf)
                if cp.has_section("user") and "default" in cp["user"]:
                    w_user = cp["user"]["default"].strip()
                    if w_user.lower() in user_dict:
                        return user_dict[w_user.lower()]
            except Exception:
                pass

        # 3. Standard Linux primary user: /etc/passwd UID 1000
        passwd = root / "etc" / "passwd"
        if passwd.exists():
            try:
                for line in passwd.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parts = line.split(":")
                    if len(parts) >= 3 and parts[2] == "1000":
                        u1000 = parts[0].strip()
                        if u1000.lower() in user_dict:
                            return user_dict[u1000.lower()]
            except Exception:
                pass

        # 4. Activity heuristic
        scored_users = []
        for name, path in user_dict.values():
            latest_mtime = 0
            for marker in [path / ".bash_history", path / ".zsh_history", path / "NTUSER.DAT", path / ".profile"]:
                try:
                    if marker.exists():
                        latest_mtime = max(latest_mtime, marker.stat().st_mtime)
                except Exception:
                    pass
            if latest_mtime == 0:
                try:
                    latest_mtime = path.stat().st_mtime
                except Exception:
                    pass
            scored_users.append((latest_mtime, (name, path)))

        if scored_users:
            scored_users.sort(key=lambda x: x[0], reverse=True)
            return scored_users[0][1]

        return None

    def _inspect_user_credentials(self, user_path: Path, os_type: str) -> DiscoveredCredentials:
        creds = DiscoveredCredentials()
        creds.detected_user = user_path.name
        creds.detected_os = os_type

        # 1. AWS Credentials
        aws_dir = user_path / ".aws"
        if aws_dir.exists():
            cred_file = aws_dir / "credentials"
            if cred_file.exists():
                creds.aws_credentials_file = cred_file
            cfg_file = aws_dir / "config"
            if cfg_file.exists():
                creds.aws_config_file = cfg_file

        # 2. Azure Credentials
        azure_dir = user_path / ".azure"
        if azure_dir.exists():
            creds.azure_config_dir = azure_dir

        # 3. GCP Credentials
        gcp_candidates = [
            user_path / ".config" / "gcloud" / "application_default_credentials.json",
            user_path / "AppData" / "Roaming" / "gcloud" / "application_default_credentials.json",
            user_path / "AppData" / "Local" / "gcloud" / "application_default_credentials.json",
        ]
        for c in gcp_candidates:
            if c.exists():
                creds.gcp_credentials_file = c
                creds.gcp_config_dir = c.parent
                break

        if not creds.gcp_config_dir:
            for gdir in [user_path / ".config" / "gcloud", user_path / "AppData" / "Roaming" / "gcloud"]:
                if gdir.exists():
                    creds.gcp_config_dir = gdir
                    break

        # 4. SSH Credentials
        ssh_dir = user_path / ".ssh"
        if ssh_dir.exists():
            creds.ssh_dir = ssh_dir
            try:
                for k in ssh_dir.iterdir():
                    if k.is_file() and not k.name.endswith(".pub"):
                        creds.ssh_keys.append(k)
            except Exception:
                pass

        return creds

    def _merge_credentials(self, target: DiscoveredCredentials, source: DiscoveredCredentials) -> None:
        if not target.aws_credentials_file and source.aws_credentials_file:
            target.aws_credentials_file = source.aws_credentials_file
            target.aws_config_file = source.aws_config_file
        elif not target.aws_config_file and source.aws_config_file:
            target.aws_config_file = source.aws_config_file

        if not target.azure_config_dir and source.azure_config_dir:
            target.azure_config_dir = source.azure_config_dir

        if not target.gcp_credentials_file and source.gcp_credentials_file:
            target.gcp_credentials_file = source.gcp_credentials_file
            target.gcp_config_dir = source.gcp_config_dir
        elif not target.gcp_config_dir and source.gcp_config_dir:
            target.gcp_config_dir = source.gcp_config_dir

        if not target.ssh_dir and source.ssh_dir:
            target.ssh_dir = source.ssh_dir
        for k in source.ssh_keys:
            if k not in target.ssh_keys:
                target.ssh_keys.append(k)

        if not target.detected_user and source.detected_user:
            target.detected_user = source.detected_user
        if not target.detected_os and source.detected_os:
            target.detected_os = source.detected_os
        if not target.root_mount and source.root_mount:
            target.root_mount = source.root_mount

    def bind_environment(self, creds: Optional[DiscoveredCredentials] = None) -> DiscoveredCredentials:
        if creds is None:
            creds = self.discover()

        if creds.aws_credentials_file and not os.environ.get("AWS_SHARED_CREDENTIALS_FILE"):
            os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(creds.aws_credentials_file)
        if creds.aws_config_file and not os.environ.get("AWS_CONFIG_FILE"):
            os.environ["AWS_CONFIG_FILE"] = str(creds.aws_config_file)

        if creds.azure_config_dir and not os.environ.get("AZURE_CONFIG_DIR"):
            os.environ["AZURE_CONFIG_DIR"] = str(creds.azure_config_dir)

        if creds.gcp_credentials_file and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds.gcp_credentials_file)
        if creds.gcp_config_dir and not os.environ.get("CLOUDSDK_CONFIG"):
            os.environ["CLOUDSDK_CONFIG"] = str(creds.gcp_config_dir)

        return creds


def get_credential_locator(target_dir: Optional[Path] = None, container_target: Optional[str] = None) -> CredentialLocator:
    """Factory returning configured CredentialLocator."""
    return CredentialLocator(target_dir=target_dir, container_target=container_target)
