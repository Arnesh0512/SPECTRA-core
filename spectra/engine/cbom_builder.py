"""
spectra.engine.cbom_builder
================================
Builds compliant CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) documents
incorporating cryptoProperties, cross-domain typed relationship edges, and Mosca quantum assessments.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
import uuid

from .correlator import CorrelatedAsset
from .mosca import MoscaEvaluation


CYCLONEDX_VERSION = "1.6"
CBOM_SCHEMA_VERSION = "http://cyclonedx.org/schema/bom-1.6.schema.json"


class CBOMBuilder:
    """Constructs a strict CycloneDX 1.6 CBOM document from correlated assets and Mosca assessments."""

    def __init__(self, application_name: str = "spectra-target", version: str = "1.0.0"):
        self.application_name = application_name
        self.version = version

    def build_cbom(
        self,
        correlated_assets: List[CorrelatedAsset],
        mosca_evaluations: Dict[str, MoscaEvaluation],
    ) -> Dict[str, Any]:
        """Generates the full CycloneDX 1.6 JSON dictionary with strict deduplication and typed dependency graph edges."""
        serial_uuid = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        bom: Dict[str, Any] = {
            "$schema": CBOM_SCHEMA_VERSION,
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_VERSION,
            "serialNumber": serial_uuid,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "spectra",
                            "version": "1.0.0",
                            "description": "Enterprise Multi-Domain Cryptographic Inventory and CBOM Engine",
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": self.application_name,
                    "version": self.version,
                },
            },
            "components": [],
            "dependencies": [],
            "vulnerabilities": [],
        }

        seen_component_refs: Set[str] = set()
        seen_vuln_ids: Set[str] = set()
        dependency_map: Dict[str, Set[str]] = {}

        for item in correlated_assets:
            asset = item.primary_asset
            bom_ref = f"crypto-ref-{asset.asset_id}"

            # Ensure every bom-ref is strictly unique in the components list
            if bom_ref in seen_component_refs:
                continue
            seen_component_refs.add(bom_ref)

            mosca = mosca_evaluations.get(asset.asset_id)

            # 1. Build Component
            component = self._build_crypto_component(bom_ref, asset, mosca)
            bom["components"].append(component)

            # 2. Accumulate Dependency Links from Correlated Typed Edges
            deps = dependency_map.setdefault(bom_ref, set())
            for rel_id in item.related_asset_ids:
                if rel_id != asset.asset_id:
                    deps.add(f"crypto-ref-{rel_id}")

            for edge in item.typed_edges:
                target_id = edge.get("to")
                # Safely handle target_id if it's a list or string
                if isinstance(target_id, list):
                    target_str = "_".join(str(t) for t in target_id)
                else:
                    target_str = str(target_id) if target_id else ""

                if target_str and target_str != asset.asset_id:
                    # If target is another component ref, add it to dependsOn
                    target_ref = f"crypto-ref-{target_str}" if not target_str.startswith("crypto-ref-") else target_str
                    deps.add(target_ref)

            # 3. Build Vulnerabilities
            vulns = self._build_vulnerability_entries(bom_ref, asset, mosca)
            for v in vulns:
                if v["id"] not in seen_vuln_ids:
                    seen_vuln_ids.add(v["id"])
                    bom["vulnerabilities"].append(v)

        # Format final deduplicated dependencies list
        for ref, depends in sorted(dependency_map.items()):
            bom["dependencies"].append({
                "ref": ref,
                "dependsOn": sorted(list(depends)),
            })

        return bom

    def save_cbom(
        self,
        cbom_dict: Dict[str, Any],
        output_file: Union[Path, str],
        indent: int = 2,
    ) -> Path:
        """Writes CBOM JSON to disk. Safely handles directory targets by appending cbom.json."""
        out = Path(output_file).expanduser().resolve()
        if out.is_dir():
            out = out / "cbom.json"
        elif out.suffix == "":
            out = out.with_suffix(".json")
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(cbom_dict, f, indent=indent)
        return out

    def _build_crypto_component(
        self,
        bom_ref: str,
        asset: Any,
        mosca: Optional[MoscaEvaluation],
    ) -> Dict[str, Any]:
        """Constructs a component with CycloneDX 1.6 cryptoProperties and quantitative Y metrics."""
        component_type = "cryptographic-asset"

        crypto_prop: Dict[str, Any] = {
            "assetType": asset.asset_type,
            "algorithmProperties": {
                "primitive": asset.primitive,
                "parameterSetIdentifier": asset.algorithm,
                "executionEnvironment": asset.source_domain,
                "implementationPlatform": "cross-platform",
            },
            "detectionContext": {
                "line": asset.location,
            },
        }

        # Key / Mode / Curve / Padding attributes
        if asset.key_size:
            crypto_prop["algorithmProperties"]["keyLength"] = asset.key_size
        if asset.mode:
            crypto_prop["algorithmProperties"]["mode"] = asset.mode
        if asset.padding:
            crypto_prop["algorithmProperties"]["padding"] = asset.padding
        if asset.curve:
            crypto_prop["algorithmProperties"]["curve"] = asset.curve

        # Quantum risk, NIST metadata, and call graph metric properties
        crypto_prop["properties"] = [
            {"name": "crypto:quantumSafe", "value": str(asset.quantum_safe).lower()},
            {"name": "crypto:shorVulnerable", "value": str(asset.shor_vulnerable).lower()},
            {"name": "crypto:nistStatus", "value": str(asset.nist_status)},
            {"name": "crypto:directCalls", "value": str(asset.direct_calls)},
            {"name": "crypto:transitiveCalls", "value": str(asset.transitive_calls)},
            {"name": "crypto:callDepth", "value": str(asset.call_depth)},
            {"name": "crypto:loc", "value": str(asset.loc)},
            {"name": "crypto:isUpstreamDependency", "value": str(asset.is_upstream_dependency).lower()},
        ]

        # Ingest scanner context (language, operation, system CA status) without emitting literal 'None'
        if hasattr(asset, "raw_metadata") and isinstance(asset.raw_metadata, dict):
            lang = asset.raw_metadata.get("language")
            if lang and str(lang).lower() != "none":
                crypto_prop["properties"].append({"name": "crypto:sourceLanguage", "value": str(lang)})
            op = asset.raw_metadata.get("operation")
            if op and str(op).lower() != "none":
                crypto_prop["properties"].append({"name": "crypto:operation", "value": str(op)})
            is_sys = asset.raw_metadata.get("is_system_ca")
            if is_sys is not None:
                crypto_prop["properties"].append({"name": "crypto:isSystemCA", "value": str(is_sys).lower()})
            scope = asset.raw_metadata.get("scope")
            if scope:
                crypto_prop["properties"].append({"name": "crypto:credentialScope", "value": str(scope)})

        if hasattr(asset, "policy_violations") and asset.policy_violations:
            for viol in asset.policy_violations:
                crypto_prop["properties"].append({
                    "name": f"policy:violation:{viol.get('rule_id')}",
                    "value": viol.get("message")
                })

        if mosca:
            crypto_prop["properties"].extend([
                {"name": "mosca:riskLevel", "value": mosca.risk_level},
                {"name": "mosca:inequalityBreached", "value": str(mosca.is_inequality_breached).lower()},
                {"name": "mosca:shelfLifeX", "value": str(mosca.shelf_life_x)},
                {"name": "mosca:migrationTimeY", "value": str(mosca.migration_time_y)},
                {"name": "mosca:quantumThresholdZ", "value": str(mosca.quantum_threshold_z)},
                {"name": "mosca:sndlVulnerable", "value": str(mosca.sndl_vulnerable).lower()},
                {"name": "mosca:recommendedPQC", "value": mosca.recommended_pqc_replacement},
            ])

        return {
            "bom-ref": bom_ref,
            "type": component_type,
            "name": asset.name,
            "cryptoProperties": crypto_prop,
        }

    def _build_vulnerability_entries(
        self,
        bom_ref: str,
        asset: Any,
        mosca: Optional[MoscaEvaluation],
    ) -> List[Dict[str, Any]]:
        """Maps discovered security issues into CycloneDX vulnerabilities."""
        vulns: List[Dict[str, Any]] = []

        # Map static scanner findings
        for idx, finding in enumerate(asset.security_findings):
            vuln_id = f"CRYPTO-VULN-{asset.asset_id}-{idx+1}"
            vulns.append({
                "id": vuln_id,
                "source": {"name": "spectra"},
                "ratings": [{
                    "severity": finding.get("severity", "MEDIUM").lower(),
                    "method": "other",
                }],
                "description": finding.get("issue", "Cryptographic compliance violation"),
                "affects": [{"ref": bom_ref}],
            })

        if hasattr(asset, "policy_violations") and asset.policy_violations:
            for idx, viol in enumerate(asset.policy_violations):
                vulns.append({
                    "id": f"POLICY-VIOLATION-{asset.asset_id}-{viol.get('rule_id', idx)}",
                    "source": {"name": "crypto-policy-engine"},
                    "ratings": [{
                        "severity": viol.get("severity", "HIGH").lower(),
                        "method": "other",
                    }],
                    "description": viol.get("message", "Policy violation"),
                    "affects": [{"ref": bom_ref}],
                })

        if mosca and mosca.is_inequality_breached:
            vulns.append({
                "id": f"MOSCA-PQC-EXP-{asset.asset_id}",
                "source": {"name": "Mosca-Theorem-Engine"},
                "ratings": [{
                    "severity": mosca.risk_level.lower(),
                    "method": "other",
                }],
                "description": mosca.rationale,
                "recommendation": f"Migrate to: {mosca.recommended_pqc_replacement}",
                "affects": [{"ref": bom_ref}],
            })

        return vulns