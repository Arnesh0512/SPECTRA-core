"""
spectra.scanners
=====================
Unified scanning layer coordinating all four reconnaissance domains:
- Source code AST and pattern analysis (source)
- Disk artifacts, certificates, binaries, and containers (artifacts)
- Infrastructure-as-Code and cloud assets (infrastructure)
- Network endpoints, TLS handshakes, and protocol configs (network)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from spectra.config import ScanConfig
from spectra.scanners.artifacts import ArtifactScanOrchestrator
from spectra.scanners.infrastructure import InfrastructureScanOrchestrator
from spectra.scanners.network import NetworkScanOrchestrator
from spectra.scanners.source import SourceScanOrchestrator
from spectra.utils.logger import log_header, log_info, log_step


@dataclass
class ScanResults:
    """Encapsulates raw findings collected across all scanning domains."""
    source_findings: List[Dict[str, Any]] = field(default_factory=list)
    artifact_findings: List[Dict[str, Any]] = field(default_factory=list)
    infrastructure_findings: List[Dict[str, Any]] = field(default_factory=list)
    network_findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def all_findings(self) -> List[Dict[str, Any]]:
        """Combines findings from all domains into a single flat list."""
        return (
            self.source_findings
            + self.artifact_findings
            + self.infrastructure_findings
            + self.network_findings
        )

    @property
    def total_count(self) -> int:
        return len(self.all_findings)


class MasterScanner:
    """Master coordinator executing enabled domain scanners against given targets."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.source_orchestrator = SourceScanOrchestrator(config=config)
        self.artifact_orchestrator = ArtifactScanOrchestrator(config=config)
        self.infrastructure_orchestrator = InfrastructureScanOrchestrator(config=config)
        self.network_orchestrator = NetworkScanOrchestrator(config=config)

    def scan_all(
        self,
        target_dir: Optional[Path] = None,
        endpoints: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> ScanResults:
        """
        Executes active scanners across configured targets.

        :param target_dir: Local filesystem directory to audit.
        :param endpoints: Optional list of network endpoints (host:port) to scan.
        :param progress_callback: Optional callback receiving (description, percent_complete).
        :return: Consolidated ScanResults instance.
        """
        results = ScanResults()
        resolved_dir = None
        if target_dir:
            try:
                if target_dir.exists():
                    if "/proc/" in str(target_dir):
                        resolved_dir = target_dir
                    else:
                        resolved_dir = target_dir.resolve()
            except (PermissionError, OSError):
                resolved_dir = target_dir

        log_header("Executing Multi-Domain Cryptographic Reconnaissance")

        # 1. Source Code & Dependency Scanning (strictly gated by enable_source)
        if resolved_dir and self.config.scanners.enable_source:
            if progress_callback:
                progress_callback("Domain 1/4: Analyzing Dependency Manifests...", 5.0)
            log_step("Domain 1/4: Source Code Analysis")
            
            all_source_raw = []
            excluded = self.config.source_scanner.excluded_directories

            # Conditionally scan dependencies if toggled on
            if self.config.scanners.scan_dependencies:
                dep_findings = self.source_orchestrator.dependency_scanner.scan_directory(
                    resolved_dir, 
                    excluded_dirs=excluded, 
                    scanners_map=self.source_orchestrator.ecosystem_to_scanner,
                    progress_callback=progress_callback
                )
                dep_decls = [f for f in dep_findings if f.raw_metadata.get("finding_type") == "crypto_capable_dependency"]
                dep_funcs = [f for f in dep_findings if f.raw_metadata.get("finding_type") == "dependency_function_analysis"]
                unique_pkgs = len(set(f.raw_metadata.get("package", "") for f in dep_decls))
                
                if dep_funcs:
                    log_info(f"Discovered {len(dep_decls)} crypto dependency declaration(s) across manifests ({unique_pkgs} unique packages) and {len(dep_funcs)} internal function mapping(s).")
                else:
                    log_info(f"Discovered {len(dep_decls)} crypto dependency declaration(s) across manifests ({unique_pkgs} unique packages).")
                all_source_raw.extend(dep_findings)

            if progress_callback:
                progress_callback("Domain 1/4: Pre-filtering Candidate Files...", 12.0)

            # Scan source AST/patterns
            candidate_files = self.source_orchestrator._find_candidates(resolved_dir)
            log_info(f"Identified {len(candidate_files)} candidate crypto source file(s) for deep analysis.")

            total_candidates = len(candidate_files)
            for idx, file_path in enumerate(candidate_files, start=1):
                main_lang = self.source_orchestrator.detect_module_main_language(file_path, resolved_dir)
                ext = file_path.suffix.lower()
                scanner = self.source_orchestrator.ext_to_scanner.get(ext)
                if scanner:
                    findings = scanner.parse_file(file_path)
                    for f in findings:
                        f.language = main_lang
                        if hasattr(f, "raw_metadata") and isinstance(f.raw_metadata, dict):
                            f.raw_metadata["module_language"] = main_lang
                            f.raw_metadata["language"] = main_lang
                    all_source_raw.extend(findings)
                if progress_callback and total_candidates > 0:
                    pct = 12.0 + (idx / total_candidates) * 28.0
                    desc = f"Domain 1/4: AST Parsing ({idx}/{total_candidates}) [{main_lang}] {file_path.name}"
                    from spectra.utils.system_paths import format_display_path
                    rel_loc = format_display_path(file_path, resolved_dir)
                    progress_callback(
                        desc,
                        pct,
                        item_info={
                            "seq": f"{idx}/{total_candidates}",
                            "type": "source code",
                            "filename": file_path.name,
                            "location": rel_loc,
                        }
                    )

            results.source_findings = [f.to_dict() for f in all_source_raw]
            log_info(f"Source scan completed: {len(results.source_findings)} findings.")
            if progress_callback:
                progress_callback("Domain 1/4: Source Code Analysis Complete", 40.0)
        else:
            log_info("Source Code Analysis skipped by user configuration.")
            if progress_callback:
                progress_callback("Domain 1/4: Skipped by Configuration", 40.0)

        # 2. Cryptographic Artifacts Scanning
        if resolved_dir and self.config.scanners.enable_artifacts:
            log_step("Domain 2/4: Cryptographic Artifacts Analysis")
            if progress_callback:
                progress_callback("Domain 2/4: Scanning Cryptographic Artifacts & Binaries...", 45.0)
            results.artifact_findings = self.artifact_orchestrator.scan(resolved_dir, progress_callback=progress_callback)
            log_info(f"Artifact scan completed: {len(results.artifact_findings)} findings.")
            if progress_callback:
                progress_callback("Domain 2/4: Cryptographic Artifacts Complete", 65.0)
        else:
            if progress_callback:
                progress_callback("Domain 2/4: Skipped by Configuration", 65.0)

        # 3. Infrastructure and Cloud Scanning
        if self.config.scanners.enable_infrastructure:
            log_step("Domain 3/4: Infrastructure & IaC Analysis")
            if progress_callback:
                progress_callback("Domain 3/4: Scanning Infrastructure & Cloud Credentials...", 70.0)
            results.infrastructure_findings = self.infrastructure_orchestrator.scan(target_dir=resolved_dir, progress_callback=progress_callback)
            log_info(f"Infrastructure scan completed: {len(results.infrastructure_findings)} findings.")
            if progress_callback:
                progress_callback("Domain 3/4: Infrastructure & IaC Complete", 85.0)
        else:
            if progress_callback:
                progress_callback("Domain 3/4: Skipped by Configuration", 85.0)

        # 4. Network and Protocol Scanning
        if self.config.scanners.enable_network:
            log_step("Domain 4/4: Network & Protocol Analysis")
            if progress_callback:
                progress_callback("Domain 4/4: Scanning Network Endpoints & TLS Protocols...", 90.0)
            net_cfg = getattr(self.config, "network", None)
            default_eps = getattr(net_cfg, "endpoints", []) if net_cfg else []
            target_eps = endpoints or default_eps
            results.network_findings = self.network_orchestrator.scan(
                target_dir=resolved_dir,
                endpoints=target_eps,
                progress_callback=progress_callback
            )
            log_info(f"Network scan completed: {len(results.network_findings)} findings.")
            if progress_callback:
                progress_callback("Domain 4/4: Network & Protocol Analysis Complete", 100.0)
        else:
            if progress_callback:
                progress_callback("Domain 4/4: Skipped by Configuration", 100.0)

        log_header(f"Reconnaissance Completed — Total Raw Findings: {results.total_count}")
        return results