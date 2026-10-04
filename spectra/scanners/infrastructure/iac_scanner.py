"""
spectra.scanners.infrastructure.iac_scanner
================================================
Static Infrastructure-as-Code (IaC) scanner for Kubernetes manifests,
Helm templates, and CloudFormation definitions.
Loaded via rules/infra_patterns.yaml.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import json
import yaml


@dataclass
class IaCFinding:
    """Represents a cryptographic resource discovered within IaC declarations."""
    source_domain: str = "infrastructure"
    infra_provider: str = "iac_manifest"  # kubernetes, cloudformation, helm
    file_path: str = ""
    line_number: int = 1
    resource_kind: str = ""
    resource_name: str = ""
    algorithm: str = "unknown"
    key_size: Optional[int] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "infra_provider": self.infra_provider,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class IaCScanner:
    """Discovers cryptographic configurations across Kubernetes and CloudFormation manifests using rules/infra_patterns.yaml."""

    YAML_EXTENSIONS = {".yaml", ".yml"}
    JSON_EXTENSIONS = {".json"}

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "infra_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        self.k8s_resources = set(self.rules.get("kubernetes_resources", ["Secret", "Ingress"]))
        self.cf_resources = set(self.rules.get("cloudformation_resources", ["AWS::KMS::Key", "AWS::CertificateManager::Certificate"]))

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _detect_manifest_type(self, file_path: Path) -> str:
        """Determines the specific IaC category purely by content/schema inspection without folder path dependence."""
        name_lower = file_path.name.lower()

        # Filename-based Docker Compose detection
        if name_lower in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
            return "compose"

        # Peek at content to identify schema structure
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                head = f.read(2048)
            head_lower = head.lower()

            # 1. Kubernetes: apiVersion and kind declarations
            if ("apiversion:" in head_lower or "apiversion " in head_lower) and ("kind:" in head_lower or "kind " in head_lower):
                return "kubernetes"

            # 2. CloudFormation: AWSTemplateFormatVersion or AWS Resources block
            if "awstemplateformatversion" in head_lower or ("resources" in head_lower and "aws::" in head_lower):
                return "cloudformation"

            # 3. Azure ARM / Bicep template: management.azure.com schema or Microsoft resource types
            if "schema.management.azure.com" in head_lower or "microsoft.keyvault" in head_lower or "microsoft.security" in head_lower:
                return "azure"

            # 4. Hardware / Security Module configurations: PKCS#11 or TPM
            if "pkcs11" in head_lower or "softhsm" in head_lower or "tpm_version" in head_lower or "tpm" in head_lower:
                return "hardware"

            # 5. Generic Docker Compose if not named docker-compose.yml
            if "services:" in head_lower and ("image:" in head_lower or "build:" in head_lower):
                return "compose"

        except Exception:
            pass

        # Fallback to generic "IaC" type if specific IaC category cannot be determined
        return "IaC"

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        excluded = set(excluded_dirs or [])

        import os
        iac_files: List[Path] = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in excluded and not any(part in excluded for part in Path(root, d).parts)]
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in self.YAML_EXTENSIONS or ext in self.JSON_EXTENSIONS:
                    iac_files.append(Path(root) / file)

        total_iac = len(iac_files)
        for idx, path in enumerate(iac_files, start=1):
            manifest_type = self._detect_manifest_type(path)
            if progress_callback and total_iac > 0:
                pct = 40.0 + (idx / total_iac) * 5.0
                desc = f"Domain 2/4: Auditing [{manifest_type}] ({idx}/{total_iac}) {path.name}"
                from spectra.utils.system_paths import format_display_path
                rel_loc = format_display_path(path, target_dir)
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_iac}",
                        "type": manifest_type,
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )
            ext = path.suffix.lower()
            if ext in self.YAML_EXTENSIONS:
                findings.extend(self._scan_yaml_file(path))
            elif ext in self.JSON_EXTENSIONS:
                findings.extend(self._scan_json_file(path))

        return findings

    def _scan_yaml_file(self, file_path: Path) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            import re
            cert_matches = re.findall(
                r'["\']?([^"\'\s\n\(\)]+\.(?:crt|pem|cer|key|p12|jks))["\']?',
                content,
                re.IGNORECASE
            )
            ssh_matches = [
                m.strip("'\"") for m in re.findall(
                    r'["\']?([^"\'\s\n\(\)]*(?:sshd_config|ssh_config|ipsec\.conf|\.ssh/config|\.ssh|network/ssh|deployments/ssh))["\']?',
                    content,
                    re.IGNORECASE
                )
                if m.strip("'\"")
            ]
            docs = yaml.safe_load_all(content)
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                # Check Kubernetes
                if "apiVersion" in doc and "kind" in doc:
                    findings.extend(self._evaluate_k8s_doc(file_path, doc))
                # Check CloudFormation
                elif "AWSTemplateFormatVersion" in doc or "Resources" in doc:
                    findings.extend(self._evaluate_cloudformation_doc(file_path, doc))

            if cert_matches or ssh_matches:
                for f in findings:
                    if cert_matches:
                        f.raw_metadata.setdefault("referenced_cert_paths", []).extend(cert_matches)
                    if ssh_matches:
                        f.raw_metadata.setdefault("referenced_ssh_paths", []).extend(ssh_matches)
                if not findings:
                    mtype = self._detect_manifest_type(file_path)
                    prov = "kubernetes" if mtype == "kubernetes" else ("cloudformation" if mtype == "cloudformation" else "iac")
                    findings.append(IaCFinding(
                        source_domain="infrastructure",
                        infra_provider=prov,
                        file_path=str(file_path.resolve()),
                        line_number=1,
                        resource_kind="manifest_crypto_reference",
                        resource_name=file_path.stem,
                        algorithm="IaC-Crypto-Reference",
                        raw_metadata={
                            "referenced_cert_paths": cert_matches,
                            "referenced_ssh_paths": ssh_matches
                        }
                    ))
        except Exception:
            return []
        return findings

    def _scan_json_file(self, file_path: Path) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            import re
            cert_matches = re.findall(
                r'["\']?([^"\'\s\n\(\)]+\.(?:crt|pem|cer|key|p12|jks))["\']?',
                content,
                re.IGNORECASE
            )
            ssh_matches = [
                m.strip("'\"") for m in re.findall(
                    r'["\']?([^"\'\s\n\(\)]*(?:sshd_config|ssh_config|ipsec\.conf|\.ssh/config|\.ssh|network/ssh|deployments/ssh))["\']?',
                    content,
                    re.IGNORECASE
                )
                if m.strip("'\"")
            ]
            data = json.loads(content)
            if isinstance(data, dict):
                if "AWSTemplateFormatVersion" in data or "Resources" in data:
                    findings.extend(self._evaluate_cloudformation_doc(file_path, data))

            if cert_matches or ssh_matches:
                for f in findings:
                    if cert_matches:
                        f.raw_metadata.setdefault("referenced_cert_paths", []).extend(cert_matches)
                    if ssh_matches:
                        f.raw_metadata.setdefault("referenced_ssh_paths", []).extend(ssh_matches)
                if not findings:
                    mtype = self._detect_manifest_type(file_path)
                    prov = "cloudformation" if mtype == "cloudformation" else ("azure" if mtype == "azure" else "iac")
                    findings.append(IaCFinding(
                        source_domain="infrastructure",
                        infra_provider=prov,
                        file_path=str(file_path.resolve()),
                        line_number=1,
                        resource_kind="manifest_crypto_reference",
                        resource_name=file_path.stem,
                        algorithm="IaC-Crypto-Reference",
                        raw_metadata={
                            "referenced_cert_paths": cert_matches,
                            "referenced_ssh_paths": ssh_matches
                        }
                    ))
        except Exception:
            return []
        return findings

    def _evaluate_k8s_doc(self, file_path: Path, doc: Dict[str, Any]) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        kind = doc.get("kind", "")
        if kind not in self.k8s_resources:
            return findings

        meta = doc.get("metadata", {})
        name = meta.get("name", "unnamed")

        # 1. TLS Secret
        if kind == "Secret":
            secret_type = doc.get("type", "")
            if secret_type == "kubernetes.io/tls":
                findings.append(IaCFinding(
                    source_domain="infrastructure",
                    infra_provider="kubernetes",
                    file_path=str(file_path.resolve()),
                    resource_kind="Secret",
                    resource_name=name,
                    algorithm="X509-TLS-Secret",
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=[],
                    raw_metadata={"secret_type": secret_type, "namespace": meta.get("namespace", "default")}
                ))

        # 2. Ingress TLS termination
        elif kind == "Ingress":
            spec = doc.get("spec", {})
            tls_blocks = spec.get("tls", [])
            for tls_entry in tls_blocks:
                secret_ref = tls_entry.get("secretName", "unspecified")
                hosts = tls_entry.get("hosts", [])
                findings.append(IaCFinding(
                    source_domain="infrastructure",
                    infra_provider="kubernetes",
                    file_path=str(file_path.resolve()),
                    resource_kind="Ingress",
                    resource_name=name,
                    algorithm="TLS-Termination",
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=[],
                    raw_metadata={"secret_name": secret_ref, "hosts": hosts}
                ))

        return findings

    def _evaluate_cloudformation_doc(self, file_path: Path, doc: Dict[str, Any]) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        resources = doc.get("Resources", {})
        if not isinstance(resources, dict):
            return []

        for logical_id, res_def in resources.items():
            if not isinstance(res_def, dict):
                continue
            res_type = res_def.get("Type", "")
            if res_type not in self.cf_resources:
                continue

            props = res_def.get("Properties", {})

            # KMS Key
            if res_type == "AWS::KMS::Key":
                key_spec = props.get("KeySpec", "SYMMETRIC_DEFAULT")
                rotation = props.get("EnableKeyRotation", False)

                sec_findings = []
                if not rotation and key_spec == "SYMMETRIC_DEFAULT":
                    sec_findings.append({
                        "issue": "CloudFormation AWS::KMS::Key defines EnableKeyRotation as false",
                        "severity": "MEDIUM"
                    })

                algo = "AES-GCM"
                quantum_safe = True
                shor_vuln = False
                key_size = 256

                if "RSA" in key_spec:
                    algo = "RSA"
                    quantum_safe = False
                    shor_vuln = True
                    key_size = 2048 if "2048" in key_spec else (3072 if "3072" in key_spec else 4096)
                elif "ECC" in key_spec:
                    algo = "ECC"
                    quantum_safe = False
                    shor_vuln = True
                    key_size = 256

                findings.append(IaCFinding(
                    source_domain="infrastructure",
                    infra_provider="cloudformation",
                    file_path=str(file_path.resolve()),
                    resource_kind=res_type,
                    resource_name=logical_id,
                    algorithm=algo,
                    key_size=key_size,
                    quantum_safe=quantum_safe,
                    shor_vulnerable=shor_vuln,
                    security_findings=sec_findings,
                    raw_metadata={"key_spec": key_spec, "rotation_enabled": rotation}
                ))

            # ACM Certificate
            elif res_type == "AWS::CertificateManager::Certificate":
                key_algo = props.get("KeyAlgorithm", "RSA_2048")
                domain = props.get("DomainName", logical_id)
                findings.append(IaCFinding(
                    source_domain="infrastructure",
                    infra_provider="cloudformation",
                    file_path=str(file_path.resolve()),
                    resource_kind=res_type,
                    resource_name=domain,
                    algorithm=key_algo,
                    key_size=2048 if "2048" in key_algo else (3072 if "3072" in key_algo else 4096),
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=[],
                    raw_metadata={"domain_name": domain, "validation_method": props.get("ValidationMethod")}
                ))

        return findings