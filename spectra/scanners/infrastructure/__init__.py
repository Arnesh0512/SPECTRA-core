"""
spectra.scanners.infrastructure
====================================
Coordinates discovery and risk auditing for infrastructure cryptographic assets:
Terraform (.tf) configurations, IaC manifests (Kubernetes, CloudFormation),
cloud environments (AWS KMS & ACM, Azure Key Vault), and host hardware devices (TPM, HSM, CPU).
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step, log_warning
from spectra.utils.credential_locator import get_credential_locator

from .aws_scanner import AWSFinding, AWSScanner
from .azure_scanner import AzureFinding, AzureScanner
from .gcp_scanner import GCPFinding, GCPScanner
from .hardware_scanner import HardwareFinding, HardwareScanner
from .iac_scanner import IaCFinding, IaCScanner
from .terraform_scanner import TerraformFinding, TerraformScanner


class InfrastructureScanOrchestrator:
    """Dispatches scanners across Terraform files, IaC manifests, hardware modules, AWS, Azure, and GCP cloud environments."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.terraform_scanner = TerraformScanner()
        self.iac_scanner = IaCScanner()
        self.hardware_scanner = HardwareScanner()

        # Safely extract AWS regions from config if present, otherwise default to us-east-1
        aws_cfg = getattr(config, "aws", None)
        regions = getattr(aws_cfg, "regions", ["us-east-1"]) if aws_cfg else ["us-east-1"]
        self.aws_scanner = AWSScanner(regions=regions)

        # Initialize Azure scanner
        self.azure_scanner = AzureScanner()

        # Initialize GCP scanner
        gcp_cfg = getattr(config, "gcp", None)
        gcp_proj = getattr(gcp_cfg, "project_id", None) if gcp_cfg else None
        gcp_locs = getattr(gcp_cfg, "locations", ["global"]) if gcp_cfg else ["global"]
        self.gcp_scanner = GCPScanner(project_id=gcp_proj, locations=gcp_locs)

    def _resolve_mounted_credentials(self, target_dir: Optional[Path]) -> None:
        """Auto-resolves credentials across Linux/WSL (/home/<user>), Windows (Users/<user>),
        and macOS mounted into container perimeters or running natively."""
        try:
            import os
            import configparser
            container_target = getattr(getattr(self.config, "scan_targets", None), "container_target", None)
            locator = get_credential_locator(target_dir=target_dir, container_target=container_target)
            creds = locator.discover()
            locator.bind_environment(creds)

            # Propagate AWS region from config file if available
            if creds.aws_config_file and creds.aws_config_file.exists():
                try:
                    cp = configparser.ConfigParser()
                    cp.read(creds.aws_config_file)
                    if cp.has_section("default") and "region" in cp["default"]:
                        reg = cp["default"]["region"].strip()
                        if reg:
                            os.environ["AWS_DEFAULT_REGION"] = reg
                            os.environ["AWS_REGION"] = reg
                            if hasattr(self, "aws_scanner"):
                                if reg not in self.aws_scanner.regions:
                                    self.aws_scanner.regions.insert(0, reg)
                except Exception:
                    pass

            if creds.has_aws:
                if hasattr(self.config, "aws") and self.config.aws:
                    self.config.aws.enabled = True
            if creds.has_azure:
                if hasattr(self.config, "azure") and self.config.azure:
                    self.config.azure.enabled = True
            if creds.has_gcp:
                if hasattr(self.config, "gcp") and self.config.gcp:
                    self.config.gcp.enabled = True

            if creds.has_aws or creds.has_azure or creds.has_gcp:
                user_info = f"user '{creds.detected_user}'" if creds.detected_user else "environment"
                os_info = f"on {creds.detected_os}" if creds.detected_os else ""
                log_info(f"Dynamic host credentials resolved for {user_info} {os_info}")
        except Exception as ex:
            log_warning(f"Could not auto-resolve host credentials: {ex}")

    def scan(self, target_dir: Optional[Path] = None, progress_callback: Optional[Callable[[str, float], None]] = None) -> List[Dict[str, Any]]:
        """Scans local Terraform directories, IaC manifests, host hardware, AWS, and Azure cloud environments."""
        self._resolve_mounted_credentials(target_dir)
        all_findings: List[Dict[str, Any]] = []
        excluded = self.config.source_scanner.excluded_directories

        # 1. Scan Terraform IaC Configurations (.tf files)
        if target_dir and target_dir.exists():
            if progress_callback:
                progress_callback("Domain 2/4: Auditing Terraform Configurations (.tf)...", 30.0)
            log_step(f"Scanning Terraform configurations in: {target_dir}")
            tf_findings: List[TerraformFinding] = self.terraform_scanner.scan_directory(
                target_dir=target_dir,
                excluded_dirs=excluded,
                progress_callback=progress_callback,
            )
            log_info(f"Discovered {len(tf_findings)} cryptographic resource(s) in Terraform files.")
            for f in tf_findings:
                all_findings.append(f.to_dict())

        # 2. Scan Generic IaC Manifests (Kubernetes YAML, CloudFormation JSON/YAML)
        if target_dir and target_dir.exists():
            if progress_callback:
                progress_callback("Domain 2/4: Auditing Generic IaC Manifests (K8s, CFN)...", 40.0)
            log_step(f"Scanning generic IaC manifests in: {target_dir}")
            iac_findings: List[IaCFinding] = self.iac_scanner.scan_directory(
                target_dir=target_dir,
                excluded_dirs=excluded,
                progress_callback=progress_callback,
            )
            log_info(f"Discovered {len(iac_findings)} cryptographic resource(s) in generic IaC manifests.")
            for f in iac_findings:
                all_findings.append(f.to_dict())

        # 3. Scan Host Hardware (TPMs, PKCS#11 HSMs, CPU Crypto Acceleration)
        if progress_callback:
            progress_callback("Domain 2/4: Auditing Host TPM & CPU Acceleration...", 45.0)
        log_step("Scanning host cryptographic hardware (TPM, HSM, CPU instruction sets)")
        hw_findings: List[HardwareFinding] = self.hardware_scanner.scan()
        log_info(f"Discovered {len(hw_findings)} hardware cryptographic device(s)/capability.")
        for f in hw_findings:
            all_findings.append(f.to_dict())

        # 4. Scan AWS Cloud Resources (KMS CMKs, ACM Certificates if enabled)
        aws_cfg = getattr(self.config, "aws", None)
        aws_enabled = getattr(aws_cfg, "enabled", False) if aws_cfg else False

        if aws_enabled:
            if progress_callback:
                progress_callback("Domain 2/4: Auditing AWS KMS & ACM Keys...", 47.0)
            log_step("Auditing AWS Cloud Cryptographic Assets (KMS & ACM)")
            if not self.aws_scanner.is_available():
                log_warning("boto3 is not installed or importable; skipping live AWS scan.")
            else:
                aws_findings: List[AWSFinding] = self.aws_scanner.scan()
                log_info(f"Discovered {len(aws_findings)} cryptographic asset(s) in AWS.")
                for idx, f in enumerate(aws_findings, 1):
                    all_findings.append(f.to_dict())
                    if progress_callback:
                        progress_callback(
                            f"Domain 2/4: Cloud KMS Key [{f.algorithm}] {f.resource_id[:16]}",
                            47.0,
                            item_info={
                                "seq": f"{idx}/{len(aws_findings)}",
                                "type": "cloud",
                                "filename": f"AWS KMS: {f.resource_id[:16]}...",
                                "location": f"{f.region} ({f.algorithm}-{f.key_size or ''})",
                            }
                        )

        # 5. Scan Azure Cloud Resources (Key Vault Keys & Certificates if enabled)
        azure_cfg = getattr(self.config, "azure", None)
        azure_enabled = getattr(azure_cfg, "enabled", False) if azure_cfg else False

        if azure_enabled:
            if progress_callback:
                progress_callback("Domain 2/4: Auditing Azure Key Vault Keys & Certs...", 48.5)
            log_step("Auditing Azure Cloud Cryptographic Assets (Key Vault Keys & Certificates)")
            if not self.azure_scanner.is_available():
                log_warning("Azure SDK libraries (azure-identity, azure-mgmt-keyvault, azure-keyvault-keys) are not installed; skipping live Azure scan.")
            else:
                azure_findings: List[AzureFinding] = self.azure_scanner.scan()
                log_info(f"Discovered {len(azure_findings)} cryptographic asset(s) in Azure.")
                for idx, f in enumerate(azure_findings, 1):
                    all_findings.append(f.to_dict())
                    if progress_callback:
                        progress_callback(
                            f"Domain 2/4: Cloud Key Vault [{f.algorithm}] {f.resource_id}",
                            48.5,
                            item_info={
                                "seq": f"{idx}/{len(azure_findings)}",
                                "type": "cloud",
                                "filename": f"Azure KV: {f.resource_id}",
                                "location": f"{f.vault_name} ({f.algorithm}-{f.key_size or ''})",
                            }
                        )

        # 6. Scan GCP Cloud Resources (Cloud KMS KeyRings & CryptoKeys if enabled)
        gcp_cfg = getattr(self.config, "gcp", None)
        gcp_enabled = getattr(gcp_cfg, "enabled", False) if gcp_cfg else False

        if gcp_enabled:
            if progress_callback:
                progress_callback("Domain 2/4: Auditing GCP Cloud KMS Keys...", 49.5)
            log_step("Auditing GCP Cloud Cryptographic Assets (Cloud KMS)")
            if not self.gcp_scanner.is_available():
                log_warning("gcloud CLI or GCP credentials not detected; skipping live GCP KMS scan.")
            else:
                gcp_findings: List[GCPFinding] = self.gcp_scanner.scan()
                log_info(f"Discovered {len(gcp_findings)} cryptographic asset(s) in GCP.")
                for idx, f in enumerate(gcp_findings, 1):
                    all_findings.append(f.to_dict())
                    if progress_callback:
                        progress_callback(
                            f"Domain 2/4: Cloud KMS Key [{f.algorithm}] {f.resource_id}",
                            49.5,
                            item_info={
                                "seq": f"{idx}/{len(gcp_findings)}",
                                "type": "cloud",
                                "filename": f"GCP KMS: {f.resource_id}",
                                "location": f"{f.key_ring} ({f.algorithm}-{f.key_size or ''})",
                            }
                        )

        return all_findings