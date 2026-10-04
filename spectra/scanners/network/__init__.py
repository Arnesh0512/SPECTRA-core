"""
spectra.scanners.network
=============================
Coordinates discovery and auditing of network cryptography:
Active TLS handshakes, static web server configurations, protocol parameters,
and low-impact DNS/port/SSH network reconnaissance.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step

from .endpoint_scanner import EndpointScanner, NetworkEndpointFinding
from .nginx_scanner import NginxFinding, NginxScanner
from .protocol_scanner import ProtocolFinding, ProtocolScanner
from .recon_scanner import NetworkReconFinding, NetworkReconScanner


class NetworkScanOrchestrator:
    """Dispatches static network configuration audits, live endpoint handshakes, and network reconnaissance."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.endpoint_scanner = EndpointScanner()
        self.nginx_scanner = NginxScanner()
        self.protocol_scanner = ProtocolScanner()
        self.recon_scanner = NetworkReconScanner()

    def scan(
        self,
        target_dir: Optional[Path] = None,
        endpoints: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> List[Dict[str, Any]]:
        """Executes static network audits, live endpoint handshakes, and reconnaissance."""
        all_findings: List[Dict[str, Any]] = []

        # 1. Static Configuration Auditing (Nginx, SSH)
        if target_dir and target_dir.exists():
            if progress_callback:
                progress_callback("Domain 3/4: Auditing Static Nginx & Protocol Configs...", 50.0)
            log_step(f"Scanning network configuration files in: {target_dir}")
            excluded = self.config.source_scanner.excluded_directories

            nginx_findings: List[NginxFinding] = self.nginx_scanner.scan_directory(
                target_dir, excluded_dirs=excluded, progress_callback=progress_callback
            )
            log_info(f"Discovered {len(nginx_findings)} Nginx/web server cryptographic block(s).")
            for nf in nginx_findings:
                all_findings.append(nf.to_dict())

            proto_findings: List[ProtocolFinding] = self.protocol_scanner.scan_directory(
                target_dir, excluded_dirs=excluded
            )
            log_info(f"Discovered {len(proto_findings)} protocol configuration(s).")
            for pf in proto_findings:
                all_findings.append(pf.to_dict())

        # 2. Live Network Endpoint Scanning & Reconnaissance
        net_cfg = getattr(self.config, "network", None)
        default_endpoints = getattr(net_cfg, "endpoints", []) if net_cfg else []
        target_endpoints = endpoints or default_endpoints

        if target_endpoints:
            if progress_callback:
                progress_callback(f"Domain 3/4: Handshaking {len(target_endpoints)} Network Endpoint(s)...", 60.0)
            log_step(f"Executing active TLS handshakes and recon against {len(target_endpoints)} endpoint(s)")
            recon_targets = self.recon_scanner.explicit_targets(target_endpoints)
            if recon_targets:
                recon_findings = self.recon_scanner.scan_targets(recon_targets)
                log_info(f"Discovered {len(recon_findings)} network reconnaissance observation(s).")
                for rf in recon_findings:
                    all_findings.append(rf.to_dict())

            total_eps = len(target_endpoints)
            for idx, ep_str in enumerate(target_endpoints, start=1):
                host, port = self._parse_endpoint(ep_str)
                if progress_callback:
                    pct = 60.0 + (idx / total_eps) * 10.0
                    progress_callback(
                        f"Domain 3/4: Handshaking {host}:{port} ({idx}/{total_eps})...",
                        pct,
                        item_info={
                            "seq": f"{idx}/{total_eps}",
                            "type": "network endpoint",
                            "filename": host,
                            "location": f"{host}:{port}",
                        }
                    )
                finding: Optional[NetworkEndpointFinding] = self.endpoint_scanner.scan_endpoint(host, port)
                if finding:
                    all_findings.append(finding.to_dict())
                    log_info(f"Handshake successful for {host}:{port} -> {finding.cipher_suite}")
                else:
                    log_info(f"Unable to complete TLS handshake with {host}:{port}")

        return all_findings

    def _parse_endpoint(self, ep_str: str) -> tuple[str, int]:
        """Parses 'example.com:8443' or 'example.com' into (host, port)."""
        ep_clean = ep_str.strip().replace("https://", "").replace("http://", "").rstrip("/")
        if ":" in ep_clean:
            parts = ep_clean.split(":")
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 443
        return ep_clean, 443