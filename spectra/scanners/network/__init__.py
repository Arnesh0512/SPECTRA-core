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
        config_discovered_ssh_paths: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Executes static network audits, live endpoint handshakes, and reconnaissance."""
        all_findings: List[Dict[str, Any]] = []

        # 1. Static Configuration Auditing (Nginx, SSH, IPsec)
        if target_dir and target_dir.exists():
            if progress_callback:
                progress_callback("Domain 3/4: Auditing Static Nginx & Protocol Configs...", 50.0)
            log_step(f"Scanning network configuration files in: {target_dir}")
            excluded = self.config.source_scanner.excluded_directories

            nginx_findings: List[NginxFinding] = []
            if getattr(self.config.scanners, "scan_nginx", True):
                nginx_findings = self.nginx_scanner.scan_directory(
                    target_dir, excluded_dirs=excluded, progress_callback=progress_callback
                )
                log_info(f"Discovered {len(nginx_findings)} Nginx/web server cryptographic block(s).")
                for nf in nginx_findings:
                    all_findings.append(nf.to_dict())

            proto_findings: List[ProtocolFinding] = []
            if getattr(self.config.scanners, "scan_protocols", True):
                proto_findings = self.protocol_scanner.scan_directory(
                    target_dir,
                    excluded_dirs=excluded,
                    progress_callback=progress_callback,
                    config_discovered_ssh_paths=config_discovered_ssh_paths,
                )
                log_info(f"Discovered {len(proto_findings)} protocol configuration(s).")
                for pf in proto_findings:
                    all_findings.append(pf.to_dict())

        # 2. Live Network Endpoint Scanning & Reconnaissance
        net_cfg = getattr(self.config, "network", None)
        default_endpoints = getattr(net_cfg, "endpoints", []) if net_cfg else []
        target_endpoints = endpoints or default_endpoints

        if target_endpoints:
            from collections import defaultdict
            import datetime as dt

            targets_map: Dict[str, set[int]] = defaultdict(set)
            host_order: List[str] = []
            for ep_str in target_endpoints:
                host, port = self._parse_endpoint(ep_str)
                if host:
                    if host not in targets_map:
                        host_order.append(host)
                    if port is not None:
                        targets_map[host].add(port)

            engine_label = "Nmap hybrid engine" if self.recon_scanner.is_nmap_available() else "native fallback engine"
            log_step(f"Executing network reconnaissance & cryptography auditing using {engine_label} across {len(host_order)} host target(s)")

            total_hosts = len(host_order)
            for h_idx, host in enumerate(host_order, start=1):
                # DNS observation
                dns_obs = self.recon_scanner.dns_lookup(host)
                addresses = [*dns_obs["records"].get("A", []), *dns_obs["records"].get("AAAA", [])]
                for ip in addresses:
                    all_findings.append(NetworkReconFinding(
                        finding_type="network_crypto_observation",
                        evidence_type="dns_resolution",
                        detected_term=ip,
                        category="network_endpoint",
                        provenance={
                            "hostname": host,
                            "resolved_ip": ip,
                            "port": None,
                            "protocol": "DNS",
                            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "target_sources": [{"source": "enterprise_input"}],
                        },
                        observation=dns_obs,
                    ).to_dict())

                req_ports = sorted(targets_map[host]) if targets_map[host] else None
                if progress_callback:
                    pct = 55.0 + ((h_idx - 1) / max(total_hosts, 1)) * 5.0
                    progress_callback(
                        f"Domain 3/4: Port & Service Discovery on {host} ({h_idx}/{total_hosts})...",
                        pct
                    )

                from spectra.utils.logger import console
                console.print(f"\n[bold cyan]• Target Host:[/bold cyan] [bold bright_white]{host}[/bold bright_white] [dim](discovering)[/dim]")

                discovered_services, engine = self.recon_scanner.discover_services(host, ports=req_ports)
                log_info(f"Discovered {len(discovered_services)} active port(s) on {host} using {engine}.")

                tot_svc = len(discovered_services)
                table_rows = []
                print_table = True
                if hasattr(self, "config"):
                    out_cfg = getattr(self.config, "output", None)
                    if out_cfg and hasattr(out_cfg, "print_table"):
                        print_table = out_cfg.print_table
                    elif hasattr(self.config, "print_table"):
                        print_table = self.config.print_table

                for s_idx, s in enumerate(discovered_services, start=1):
                    port = s["port"]
                    svc_name = s.get("service") or "unknown"
                    product = s.get("product", "")
                    version = s.get("version", "")
                    is_tls = s.get("is_tls", False)
                    is_ssh = s.get("is_ssh", False)

                    loc_str = f"{host}:{port} ({svc_name})"
                    if progress_callback:
                        pct = 60.0 + (s_idx / max(tot_svc, 1)) * 10.0
                        progress_callback(
                            f"Domain 3/4: Auditing {loc_str} ({s_idx}/{tot_svc})...",
                            pct
                        )

                    # Branch A: SSL/TLS Endpoints
                    if is_tls:
                        finding: Optional[NetworkEndpointFinding] = self.endpoint_scanner.scan_endpoint(host, port)
                        if finding:
                            finding.raw_metadata["service"] = svc_name
                            finding.raw_metadata["service_product"] = product
                            finding.raw_metadata["service_version"] = version
                            finding.raw_metadata["discovery_engine"] = engine
                            all_findings.append(finding.to_dict())
                            crypto_label = f"[bold green]{finding.cipher_suite}[/bold green]"
                            if finding.tls_version and finding.tls_version != "Unknown":
                                crypto_label += f" [dim]({finding.tls_version})[/dim]"
                            table_rows.append({
                                "seq": f"{s_idx}/{tot_svc}",
                                "type": "https" if svc_name in ["http", "unknown"] else svc_name,
                                "port": f"{port}/tcp",
                                "handshake": "[bold green]✔[/bold green]",
                                "crypto": crypto_label,
                            })
                        else:
                            failed_ep = NetworkEndpointFinding(
                                source_domain="network",
                                target=host,
                                port=port,
                                tls_version="Handshake Failed",
                                cipher_suite="Unknown",
                                security_findings=[{
                                    "issue": f"TLS handshake failed or connection rejected on open port {port} ({svc_name})",
                                    "severity": "LOW"
                                }],
                                raw_metadata={
                                    "service": svc_name,
                                    "product": product,
                                    "version": version,
                                    "discovery_engine": engine,
                                    "handshake_failed": True,
                                }
                            )
                            all_findings.append(failed_ep.to_dict())
                            table_rows.append({
                                "seq": f"{s_idx}/{tot_svc}",
                                "type": svc_name,
                                "port": f"{port}/tcp",
                                "handshake": "[bold red]✖[/bold red]",
                                "crypto": "[dim red]TLS Handshake Failed[/dim red]",
                            })

                    # Branch B: SSH Endpoints
                    elif is_ssh:
                        ssh_obs = self.recon_scanner.ssh_keyscan(host, port, timeout=5)
                        if ssh_obs:
                            for obs in ssh_obs:
                                obs["service"] = "ssh"
                                obs["product"] = product
                                obs["version"] = version
                                obs["discovery_engine"] = engine
                                algo = obs.get("host_key_algorithm", "SSH-Host-Key")
                                all_findings.append(NetworkReconFinding(
                                    finding_type="network_crypto_observation",
                                    evidence_type="ssh_host_key",
                                    detected_term=algo,
                                    category="host_key",
                                    provenance={
                                        "hostname": host,
                                        "resolved_ip": addresses[0] if addresses else None,
                                        "port": port,
                                        "protocol": "SSH",
                                        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                                        "target_sources": [{"source": "enterprise_input"}],
                                    },
                                    observation=obs,
                                ).to_dict())
                            algo_first = ssh_obs[0].get("host_key_algorithm", "SSH-Host-Key")
                            table_rows.append({
                                "seq": f"{s_idx}/{tot_svc}",
                                "type": "ssh",
                                "port": f"{port}/tcp",
                                "handshake": "[bold green]✔[/bold green]",
                                "crypto": f"[bold cyan]{algo_first}[/bold cyan]",
                            })
                        else:
                            all_findings.append(NetworkReconFinding(
                                finding_type="network_crypto_observation",
                                evidence_type="open_tcp_port",
                                detected_term=str(port),
                                category="network_service_candidate",
                                provenance={
                                    "hostname": host,
                                    "resolved_ip": addresses[0] if addresses else None,
                                    "port": port,
                                    "protocol": "SSH",
                                    "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                                    "target_sources": [{"source": "enterprise_input"}],
                                },
                                observation={
                                    "port": port,
                                    "service": "ssh",
                                    "product": product,
                                    "version": version,
                                    "discovery_engine": engine,
                                },
                            ).to_dict())
                            table_rows.append({
                                "seq": f"{s_idx}/{tot_svc}",
                                "type": "ssh",
                                "port": f"{port}/tcp",
                                "handshake": "[bold yellow]?[/bold yellow]",
                                "crypto": "[dim]Open SSH Port[/dim]",
                            })

                    # Branch C: Cleartext / Non-cryptographic services (HTTP, Redis, etc.)
                    else:
                        sev = "HIGH" if svc_name.lower() in {"telnet", "ftp", "http"} else "MEDIUM"
                        prod_str = f" ({product} {version})".strip() if product else ""
                        cleartext_ep = NetworkEndpointFinding(
                            source_domain="network",
                            target=host,
                            port=port,
                            tls_version="None (Cleartext)",
                            cipher_suite=f"Cleartext-{svc_name.upper()}",
                            key_exchange="None",
                            symmetric_cipher="None",
                            mac_algorithm="None",
                            quantum_safe=False,
                            shor_vulnerable=False,
                            security_findings=[{
                                "issue": f"Unencrypted cleartext transport detected for {svc_name.upper()} service on port {port}{prod_str}",
                                "severity": sev
                            }],
                            raw_metadata={
                                "service": svc_name,
                                "product": product,
                                "version": version,
                                "cleartext": True,
                                "discovery_engine": engine,
                            }
                        )
                        all_findings.append(cleartext_ep.to_dict())
                        table_rows.append({
                            "seq": f"{s_idx}/{tot_svc}",
                            "type": svc_name,
                            "port": f"{port}/tcp",
                            "handshake": "[bold red]✖[/bold red]",
                            "crypto": f"[dim yellow]Cleartext ({svc_name.upper()})[/dim yellow]",
                        })

                    if not print_table and progress_callback and table_rows:
                        latest_row = table_rows[-1]
                        import re
                        plain_crypto = re.sub(r'\[/?[a-zA-Z0-9_\-\s=]+\]', '', latest_row['crypto'])
                        progress_callback(
                            f"Domain 3/4: Auditing {loc_str} ({s_idx}/{tot_svc})...",
                            pct,
                            item_info={
                                "seq": latest_row["seq"],
                                "type": latest_row["type"],
                                "filename": f"{host}:{port}",
                                "location": plain_crypto,
                            }
                        )

                if print_table and table_rows:
                    from rich.table import Table
                    from rich import box
                    net_table = Table(
                        box=box.ROUNDED,
                        border_style="cyan",
                        show_header=True,
                        header_style="bold bright_cyan",
                        expand=False,
                    )
                    net_table.add_column("Seq", justify="center", width=8)
                    net_table.add_column("Type", justify="left", width=12)
                    net_table.add_column("Port", justify="center", width=10)
                    net_table.add_column("TLS Handshake", justify="center", width=16)
                    net_table.add_column("Cryptographic Cipher Suite / Finding", justify="left", min_width=38)

                    for r in table_rows:
                        net_table.add_row(r["seq"], r["type"], r["port"], r["handshake"], r["crypto"])

                    console.print(net_table)

        return all_findings

    def _parse_endpoint(self, ep_str: str) -> tuple[str, Optional[int]]:
        """Parses 'example.com:8443' or 'example.com' into (host, port_or_none)."""
        ep_clean = ep_str.strip().replace("https://", "").replace("http://", "").rstrip("/")
        if ":" in ep_clean:
            parts = ep_clean.split(":")
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], None
        return ep_clean, None