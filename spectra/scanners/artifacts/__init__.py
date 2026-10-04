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
from .hardware_scanner import HardwareFinding, HardwareScanner
from .runtime_scanner import RuntimeFinding, RuntimeScanner


class ArtifactScanOrchestrator:
    """Dispatches artifact, hardware, and runtime scanners across target environments."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.cert_scanner = CertScanner()
        self.binary_scanner = BinaryScanner()
        self.hardware_scanner = HardwareScanner()
        self.runtime_scanner = RuntimeScanner()

    def scan(
        self,
        target_dir: Path,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        config_discovered_certs: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Scans directory for artifacts, hardware capabilities, and inspects local runtime environment."""
        log_step(f"Scanning cryptographic artifacts and runtime in: {target_dir}")
        excluded = self.config.source_scanner.excluded_directories

        # 1. Scan Certificates & Keys
        scan_certs_enabled = getattr(self.config.scanners, "scan_certificates", True)
        cert_findings: List[CertFinding] = []
        if scan_certs_enabled:
            include_sys = getattr(self.config.scanners, "include_system_certs", False)
            if progress_callback:
                progress_callback("Domain 4/4: Auditing X.509 Certificates & Asymmetric Keys...", 70.0)
            cert_findings = self.cert_scanner.scan_directory(
                target_dir,
                excluded_dirs=excluded,
                include_system_certs=include_sys,
                progress_callback=progress_callback,
                config_discovered_certs=config_discovered_certs,
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
        binary_findings: List[BinaryFinding] = []
        if getattr(self.config.scanners, "scan_binaries", True):
            if progress_callback:
                progress_callback("Domain 4/4: Auditing Executable Binaries & Shared Libraries...", 82.0)
            binary_findings = self.binary_scanner.scan_directory(
                target_dir, excluded_dirs=excluded, progress_callback=progress_callback
            )
            log_info(f"Discovered {len(binary_findings)} binary/library artifact(s) with crypto linkage.")

        # 3. Scan Host Hardware (TPMs, PKCS#11 HSMs, CPU Crypto Acceleration)
        hw_findings: List[HardwareFinding] = []
        if getattr(self.config.scanners, "scan_hardware", True):
            if progress_callback:
                progress_callback("Domain 4/4: Auditing Host TPM, HSM & CPU Crypto Hardware...", 90.0)
            log_step("Scanning host cryptographic hardware (TPM, HSM, CPU instruction sets)")
            hw_findings = self.hardware_scanner.scan(target_dir=target_dir)
            log_info(f"Discovered {len(hw_findings)} hardware cryptographic device(s)/capability.")
            total_hw = len(hw_findings)
            for idx, f in enumerate(hw_findings, 1):
                if progress_callback and total_hw > 0:
                    feat = f.raw_metadata.get("features", [])
                    feat_str = f"[{', '.join(feat).upper()}] " if feat else ""
                    loc = f.raw_metadata.get("sysfs_path") or f.raw_metadata.get("dev_path") or f.raw_metadata.get("module_path") or f.raw_metadata.get("platform") or f.algorithm
                    if feat_str:
                        loc = f"{feat_str}{loc}"
                    progress_callback(
                        f"Domain 4/4: Host Crypto Hardware ({idx}/{total_hw}) {f.device_name}",
                        90.0 + (idx / total_hw) * 5.0,
                        item_info={
                            "seq": f"{idx}/{total_hw}",
                            "type": "hardware",
                            "filename": f.device_name,
                            "location": loc,
                        }
                    )

        # 4. Scan Active Runtime Environment (Processes, loaded .so files, python packages)
        runtime_findings: List[RuntimeFinding] = []
        if getattr(self.config.scanners, "enable_runtime", True):
            if progress_callback:
                progress_callback("Domain 4/4: Inspecting Process Memory & Dynamic Runtime Packages...", 96.0)
            c_target = getattr(getattr(self.config, "scan_targets", None), "container_target", None)
            runtime_findings = self.runtime_scanner.scan(target_dir=target_dir, container_name=c_target)
            log_info(f"Discovered {len(runtime_findings)} active runtime package/process finding(s).")
            total_rt = len(runtime_findings)
            for idx, rf in enumerate(runtime_findings, 1):
                if progress_callback and total_rt > 0:
                    pids = rf.raw_metadata.get("pids", [])
                    procs = rf.raw_metadata.get("processes", [])
                    proc_tag = f"[{','.join(procs[:2])}] " if procs else ""
                    pid_tag = f"PID: {','.join(pids[:2])} " if pids else ""
                    loc_desc = f"{proc_tag}{pid_tag}({rf.file_path})"
                    progress_callback(
                        f"Domain 4/4: Active Runtime Process ({idx}/{total_rt}) {Path(rf.file_path).name}",
                        96.0 + (idx / total_rt) * 3.0,
                        item_info={
                            "seq": f"{idx}/{total_rt}",
                            "type": "runtime",
                            "filename": Path(rf.file_path).name,
                            "location": loc_desc,
                        }
                    )

        all_findings: List[Dict[str, Any]] = []
        for c in cert_findings:
            all_findings.append(c.to_dict())
        for b in binary_findings:
            all_findings.append(b.to_dict())
        for hw in hw_findings:
            all_findings.append(hw.to_dict())
        for rt in runtime_findings:
            all_findings.append(rt.to_dict())

        return all_findings