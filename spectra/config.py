"""
spectra.config
===================
Dynamic programmatic configuration builder for Spectra interactive TUI.
"""

from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ScanTargets(BaseModel):
    project_root: str = Field(default=".", description="Root directory to scan for code and artifacts")
    container_target: Optional[str] = Field(default=None, description="Name or ID of Docker container scanned")
    domains: List[str] = Field(default_factory=list, description="Remote host:port targets for TLS inspection")
    aws_regions: List[str] = Field(default_factory=lambda: ["us-east-1"], description="AWS regions for discovery")
    nginx_config_paths: List[str] = Field(default_factory=list, description="Filesystem paths to nginx configurations")


class ScannerToggles(BaseModel):
    enable_source: bool = Field(default=True, description="Scan source code AST and patterns")
    enable_artifacts: bool = Field(default=True, description="Scan binaries, certs, and hardware")
    enable_runtime: bool = Field(default=True, description="Scan active local runtime packages and processes")
    enable_infrastructure: bool = Field(default=True, description="Scan AWS/Azure KMS/ACM and Terraform/Docker")
    enable_network: bool = Field(default=True, description="Scan endpoints, TLS handshakes, and web servers")
    scan_dependencies: bool = Field(default=True, description="Scan dependency manifests")
    scan_certificates: bool = Field(default=True, description="Scan X.509 certificates and keys")
    include_system_certs: bool = Field(default=False, description="Scan preinstalled OS root CA trust store")
    scan_docker: bool = Field(default=True, description="Scan Dockerfiles and container manifests")
    scan_hardware: bool = Field(default=True, description="Scan host cryptographic hardware (TPM, HSM, CPU)")
    scan_binaries: bool = Field(default=True, description="Scan binary executables and shared libraries")
    scan_terraform: bool = Field(default=True, description="Scan Terraform and IaC configurations")
    scan_nginx: bool = Field(default=True, description="Scan Nginx configurations for crypto blocks")
    scan_protocols: bool = Field(default=True, description="Scan SSH and IPsec protocol configurations")


class SourceScannerConfig(BaseModel):
    use_ripgrep: bool = Field(default=True, description="Always true for optimized AST matching")
    max_header_lines_checked: int = Field(default=100, description="Header lines evaluated")
    excluded_directories: List[str] = Field(
        default_factory=lambda: [
            ".git", "node_modules", "vendor", "target",
            "dist", "build", ".venv", "venv", "__pycache__",
            "proc", "sys", "dev", "run"
        ],
        description="Directories ignored across all filesystem walkers"
    )


class NetworkConfig(BaseModel):
    endpoints: List[str] = Field(default_factory=list, description="Remote host:port targets for TLS inspection")


def _get_default_aws_regions() -> List[str]:
    detected: List[str] = []
    try:
        import boto3
        sess = boto3.Session()
        if sess.region_name:
            detected.append(sess.region_name)
    except Exception:
        pass
    import os
    env_reg = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
    if env_reg and env_reg not in detected:
        detected.append(env_reg)
    if "us-east-1" not in detected:
        detected.append("us-east-1")
    return detected


def _is_aws_enabled() -> bool:
    import os
    if bool(os.environ.get("AWS_SHARED_CREDENTIALS_FILE")) or bool(os.environ.get("AWS_ACCESS_KEY_ID")):
        return True
    try:
        from spectra.utils.credential_locator import get_credential_locator
        return get_credential_locator().discover().has_aws
    except Exception:
        return (Path.home() / ".aws").exists()


def _is_azure_enabled() -> bool:
    import os
    if bool(os.environ.get("AZURE_CONFIG_DIR")) or bool(os.environ.get("AZURE_CLIENT_ID")):
        return True
    try:
        from spectra.utils.credential_locator import get_credential_locator
        return get_credential_locator().discover().has_azure
    except Exception:
        return (Path.home() / ".azure").exists()


class AWSConfig(BaseModel):
    enabled: bool = Field(
        default_factory=_is_aws_enabled,
        description="Auto-enabled if AWS credentials exist"
    )
    regions: List[str] = Field(default_factory=_get_default_aws_regions, description="AWS regions to scan")


class AzureConfig(BaseModel):
    enabled: bool = Field(
        default_factory=_is_azure_enabled,
        description="Auto-enabled if Azure credentials exist"
    )
    subscription_id: Optional[str] = Field(default=None, description="Azure subscription ID")


def _is_gcp_configured() -> bool:
    import os, shutil
    if bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")) or bool(os.environ.get("CLOUDSDK_CONFIG")):
        return True
    if shutil.which("gcloud") is not None:
        return True
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data and (Path(local_app_data) / "Google" / "Cloud SDK" / "google-cloud-sdk" / "bin" / "gcloud.cmd").exists():
        return True
    try:
        from spectra.utils.credential_locator import get_credential_locator
        return get_credential_locator().discover().has_gcp
    except Exception:
        return (Path.home() / ".config" / "gcloud" / "application_default_credentials.json").exists()


class GCPConfig(BaseModel):
    enabled: bool = Field(
        default_factory=_is_gcp_configured,
        description="Auto-enabled if gcloud CLI or GCP credentials exist"
    )
    project_id: Optional[str] = Field(default=None, description="GCP project ID")
    locations: List[str] = Field(default_factory=lambda: ["global"], description="GCP locations to scan")


class MoscaConfig(BaseModel):
    default_data_classification: str = Field(default="corporate_financials", description="Default shelf life profile")
    crqc_scenario: str = Field(default="central", description="pessimistic, central, or optimistic")
    environment_type: str = Field(default="cloud_native", description="cloud_native, hybrid, on_prem_legacy, embedded")


class OutputConfig(BaseModel):
    format: str = Field(default="cyclonedx_1.6_json", description="Target CBOM export format")
    output_file: str = Field(default="cbom.json", description="Destination file for generated CBOM")
    print_table: bool = Field(default=True, description="Whether to print full scanning discovery tables")


class ScanConfig(BaseModel):
    scan_targets: ScanTargets = Field(default_factory=ScanTargets)
    scanners: ScannerToggles = Field(default_factory=ScannerToggles)
    source_scanner: SourceScannerConfig = Field(default_factory=SourceScannerConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    gcp: GCPConfig = Field(default_factory=GCPConfig)
    mosca_parameters: MoscaConfig = Field(default_factory=MoscaConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)