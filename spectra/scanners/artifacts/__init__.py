"""
spectra.scanners.artifacts
===============================
Coordinates discovery and auditing of cryptographic artifacts:
X.509 certificates, private keys, compiled binaries, shared libraries,
container definitions, and active local runtime environments.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step

from .binary_scanner import BinaryFinding, BinaryScanner
from .cert_scanner import CertFinding, CertScanner
from .container_scanner import ContainerFinding, ContainerScanner
from .runtime_scanner import RuntimeFinding, RuntimeScanner


class ArtifactScanOrchestrator:
    """Dispatches artifact and runtime scanners across target environments."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.cert_scanner = CertScanner()
        self.binary_scanner = BinaryScanner()
        self.container_scanner = ContainerScanner()
        self.runtime_scanner = RuntimeScanner()

    def scan(self, target_dir: Path, progress_callback: Optional[Callable[[str, float], None]] = None) -> List[Dict[str, Any]]:
        """Scans directory for artifacts, and inspects local runtime environment if enabled."""
        log_step(f"Scanning cryptographic artifacts and runtime in: {target_dir}")
        excluded = self.config.source_scanner.excluded_directories

        # 1. Scan Certificates & Keys
        scan_certs_enabled = getattr(self.config.scanners, "scan_certificates", True)
        cert_findings: List[CertFinding] = []
        if scan_certs_enabled:
            include_sys = getattr(self.config.scanners, "include_system_certs", False)
            if progress_callback:
                progress_callback("Domain 2/4: Auditing X.509 Certificates & Asymmetric Keys...", 45.0)
            cert_findings = self.cert_scanner.scan_directory(
                target_dir,
                excluded_dirs=excluded,
                include_system_certs=include_sys,
                progress_callback=progress_callback
            )
            project_count = sum(1 for c in cert_findings if not c.is_system_ca)
            system_count = sum(1 for c in cert_findings if c.is_system_ca)
            if include_sys:
                log_info(f"Discovered {project_count} project certificate/key artifact(s) and {system_count} preinstalled OS root CA(s).")
            else:
                log_info(f"Discovered {project_count} project certificate/key artifact(s) (preinstalled OS root CAs bypassed).")
        else:
            log_info("Certificate and key scanning bypassed by configuration.")

        # 2. Scan Binaries & Shared Libraries
        if progress_callback:
            progress_callback("Domain 2/4: Auditing Executable Binaries & Shared Libraries...", 52.0)
        binary_findings: List[BinaryFinding] = self.binary_scanner.scan_directory(
            target_dir, excluded_dirs=excluded, progress_callback=progress_callback
        )
        log_info(f"Discovered {len(binary_findings)} binary/library artifact(s) with crypto linkage.")

        # 3. Scan Container Definitions & Dockerfiles
        if progress_callback:
            progress_callback("Domain 2/4: Auditing Container Definitions & Dockerfiles...", 58.0)
        container_findings: List[ContainerFinding] = self.container_scanner.scan_directory(
            target_dir, excluded_dirs=excluded, progress_callback=progress_callback
        )
        log_info(f"Discovered {len(container_findings)} container cryptographic finding(s).")

        # 4. Scan Active Runtime Environment (Processes, loaded .so files, python packages)
        runtime_findings: List[RuntimeFinding] = []
        if getattr(self.config.scanners, "enable_runtime", True):
            if progress_callback:
                progress_callback("Domain 2/4: Inspecting Process Memory & Dynamic Runtime Packages...", 62.0)
            runtime_findings = self.runtime_scanner.scan(target_dir)
            log_info(f"Discovered {len(runtime_findings)} active runtime package/process finding(s).")

        all_findings: List[Dict[str, Any]] = []
        for c in cert_findings:
            all_findings.append(c.to_dict())
        for b in binary_findings:
            all_findings.append(b.to_dict())
        for ct in container_findings:
            all_findings.append(ct.to_dict())
        for rt in runtime_findings:
            all_findings.append(rt.to_dict())

        return all_findings