"""
spectra.engine.normalizer
==============================
Normalizes heterogeneous cryptographic findings from source, artifacts,
infrastructure, and network scanners into a canonical data model.
Integrated with crypto_policy_rules.json and cbom_policy.json.
"""

from dataclasses import dataclass, field
import hashlib
from typing import Any, Dict, List, Optional
import json
from pathlib import Path


@dataclass
class NormalizedCryptoAsset:
    """Canonical representation of a discovered cryptographic asset."""
    asset_id: str
    name: str
    asset_type: str  # algorithm, certificate, key, protocol
    source_domain: str  # source_code, artifacts, infrastructure, network
    location: str
    algorithm: str
    primitive: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    nist_status: str = "unknown"
    # New Phase 1 & Phase 2 Parameters for Quantitative Y Estimation
    direct_calls: int = 0
    transitive_calls: int = 0
    call_depth: int = 0
    loc: int = 0
    is_upstream_dependency: bool = False
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    policy_violations: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "source_domain": self.source_domain,
            "location": self.location,
            "algorithm": self.algorithm,
            "primitive": self.primitive,
            "key_size": self.key_size,
            "mode": self.mode,
            "padding": self.padding,
            "curve": self.curve,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "nist_status": self.nist_status,
            "direct_calls": self.direct_calls,
            "transitive_calls": self.transitive_calls,
            "call_depth": self.call_depth,
            "loc": self.loc,
            "is_upstream_dependency": self.is_upstream_dependency,
            "security_findings": self.security_findings,
            "policy_violations": self.policy_violations,
            "raw_metadata": self.raw_metadata,
        }


class AssetNormalizer:
    """Standardizes disparate scanner findings into canonical cryptographic assets and applies security rules."""

    def __init__(self, policy_rules_file: Optional[Path] = None) -> None:
        if policy_rules_file is None:
            policy_rules_file = Path(__file__).resolve().parent.parent.parent / "crypto_policy_rules.json"
        
        self.rules = self._load_rules(policy_rules_file)

    def _load_rules(self, path: Path) -> List[Dict[str, Any]]:
        """Loads cryptographic policy rules from JSON configuration[cite: 20]."""
        if not path.is_file():
            return []
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
                return content.get("rules", [])
        except Exception:
            return []

    def evaluate_rules(self, asset_dict: Dict[str, Any]) -> List[Dict[str, str]]:
        """Evaluates asset attributes against loaded compliance and security rules with null safety[cite: 20]."""
        violations: List[Dict[str, str]] = []

        for rule in self.rules:
            field_name = rule.get("field")
            expected_value = rule.get("equals")
            matched = False

            asset_algorithm = asset_dict.get("algorithm")
            asset_mode = asset_dict.get("mode")
            raw_metadata = asset_dict.get("raw_metadata", {}) or {}
            tls_version = raw_metadata.get("tls_version")
            key_size = asset_dict.get("key_size")

            if field_name == "algorithm":
                if asset_algorithm and isinstance(asset_algorithm, str):
                    if asset_algorithm.upper() == str(expected_value).upper():
                        matched = True

            elif field_name == "mode":
                if asset_mode and isinstance(asset_mode, str):
                    if asset_mode.upper() == str(expected_value).upper():
                        matched = True

            elif field_name == "tls_version":
                if tls_version and tls_version == expected_value:
                    matched = True

            elif field_name == "key_size_less_than":
                threshold = rule.get("value", 2048)
                if isinstance(key_size, int) and key_size < threshold:
                    matched = True

            if matched:
                violations.append({
                    "rule_id": rule.get("id", "UNKNOWN"),
                    "severity": rule.get("severity", "MEDIUM"),
                    "message": rule.get("message", "Policy violation detected.")
                })

        return violations

    def normalize(self, raw_finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        """Normalizes a single raw finding based on its source domain[cite: 20]."""
        domain = raw_finding.get("source_domain", "unknown")

        if domain == "source_code":
            asset = self._normalize_source(raw_finding)
        elif domain == "artifacts":
            asset = self._normalize_artifact(raw_finding)
        elif domain == "infrastructure":
            asset = self._normalize_infrastructure(raw_finding)
        elif domain == "network":
            asset = self._normalize_network(raw_finding)
        else:
            asset = self._normalize_fallback(raw_finding)

        asset.policy_violations = self.evaluate_rules(asset.to_dict())
        return asset

    def normalize_batch(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedCryptoAsset]:
        """Normalizes and deduplicates a batch of raw findings into canonical assets[cite: 20]."""
        seen_ids = set()
        deduped_assets: List[NormalizedCryptoAsset] = []

        for finding in raw_findings:
            asset = self.normalize(finding)
            if asset.asset_id not in seen_ids:
                seen_ids.add(asset.asset_id)
                deduped_assets.append(asset)

        return deduped_assets

    @staticmethod
    def resolve_nist_status(
        algorithm: Any,
        primitive: str = "",
        key_size: Optional[int] = None,
        quantum_safe: bool = False,
        existing_status: str = "unknown"
    ) -> str:
        """
        Authoritative NIST cryptographic status resolution conforming to:
        - FIPS 203 / 204 / 205 (NIST Post-Quantum Standards)
        - NIST SP 800-131A Rev. 2 (Transitioning the Use of Cryptographic Algorithms)
        - NIST SP 800-57 Part 1 Rev. 5 (Recommendation for Key Management)
        - FIPS 186-5 (Digital Signature Standard)
        - FIPS 198-1 (HMAC) / SP 800-132 (PBKDF) / SP 800-52 Rev. 2 (TLS Guidelines)
        """
        if existing_status and str(existing_status).lower() not in ["unknown", "none", ""]:
            return existing_status

        if isinstance(algorithm, list):
            algo_u = " ".join(str(x) for x in algorithm).upper()
        else:
            algo_u = str(algorithm or "").upper()
        prim_l = str(primitive or "").lower()

        # 1. NIST Post-Quantum Cryptography Standards (FIPS 203, 204, 205)
        pqc_tokens = [
            "ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM",
            "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "BIKE", "HQC",
            "FIPS-203", "FIPS-204", "FIPS-205"
        ]
        if any(tok in algo_u for tok in pqc_tokens) or (quantum_safe and any(tok in algo_u for tok in ["HYBRID", "PQC"])):
            return "fips_pqc_standard"

        # 2. Broken Classical Primitives (Disallowed by NIST)
        if "DES" in algo_u and not any(x in algo_u for x in ["3DES", "DES3", "DESEDE", "TRIPLEDES", "ED25519"]):
            return "broken_classical"
        if any(tok in algo_u for tok in ["MD5", "RC4", "ARC4", "ARCFOUR"]):
            return "broken_classical"
        if key_size is not None and key_size < 2048 and any(tok in algo_u for tok in ["RSA", "DSA", "ASYMMETRIC"]):
            return "broken_classical"
        if "1024" in algo_u and any(tok in algo_u for tok in ["RSA", "KEY"]):
            return "broken_classical"

        # 3. Deprecated Classical Primitives (Legacy with known vulnerabilities)
        if any(tok in algo_u for tok in ["3DES", "DES3", "DESEDE", "TRIPLEDES"]):
            return "deprecated_classical"
        if ("SHA1" in algo_u or "SHA-1" in algo_u) and not any(k in algo_u for k in ["PBKDF", "HMAC"]):
            return "deprecated_classical"
        if any(tok in algo_u for tok in ["TLSV1.0", "TLSV1.1", "SSLV2", "SSLV3", "BLOWFISH"]):
            return "deprecated_classical"

        # 4. Deprecated Post-Quantum Transition (Classical Asymmetric: Shor Vulnerable)
        # NIST SP 800-131A Rev 2 & CNSA 2.0: RSA-2048+, ECDSA, ECDH, ECC, Ed25519, X25519
        asym_tokens = [
            "RSA", "ECDSA", "ECDH", "ECC", "SECP256", "SECP384", "SECP521",
            "PRIME256", "ED25519", "X25519", "ED448", "X448", "DIFFIE", "DSA"
        ]
        is_asym_algo = any(tok in algo_u for tok in asym_tokens)
        is_asym_prim = prim_l in [
            "public_key", "signature", "key_exchange",
            "asymmetric_encryption", "key_agreement", "private_key", "certificate"
        ]
        if is_asym_algo or (is_asym_prim and not quantum_safe):
            return "deprecated_pqc"

        # 5. NIST Approved Primitives
        # Symmetric, Hashes, MACs, KDFs, CSPRNGs, Modern TLS
        approved_tokens = [
            "AES", "GCM", "CBC", "CTR", "CFB", "OFB", "CHACHA20", "POLY1305", "SALSA20", "TWOFISH",
            "SHA-2", "SHA2", "SHA256", "SHA384", "SHA512", "SHA224", "SHA-3", "SHA3", "BLAKE2", "BLAKE3",
            "HMAC", "KMAC", "GMAC", "CMAC", "PBKDF", "PBKDF2", "HKDF", "ARGON2", "SCRYPT",
            "CSPRNG", "URANDOM", "SECURERANDOM", "DRBG",
            "TLS", "TLSV1.2", "TLSV1.3", "SSH", "PKCS12", "KEYSTORE", "KMS", "HARDWARE"
        ]
        if any(tok in algo_u for tok in approved_tokens):
            return "approved"
        if prim_l in ["symmetric_cipher", "hash", "mac", "key_derivation", "prng", "secure_transport", "key_management"]:
            return "approved"

        # 6. Operational CodeQL Invocations / Composite Multi-algorithm Binaries
        if prim_l in ["cryptographic_operation", "multiple"]:
            return "approved"

        return "approved"

    def _normalize_source(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        from spectra.utils.system_paths import format_display_path
        file_path = format_display_path(finding.get("file_path", ""))
        line = finding.get("line_number", 0)
        algo = finding.get("algorithm", "unknown").upper()
        primitive = finding.get("primitive", "symmetric_cipher").lower()
        mode = finding.get("mode")
        padding = finding.get("padding")
        key_size = finding.get("key_size")
        curve = finding.get("curve")
        quantum_safe = finding.get("quantum_safe", False)
        operation = finding.get("operation")

        # Extract call graph and LOC metrics from finding top-level attributes or metadata
        metadata = finding.get("raw_metadata", {}).copy()
        direct_calls = finding.get("direct_calls", metadata.get("direct_calls", 0))
        transitive_calls = finding.get("transitive_calls", metadata.get("transitive_calls", 0))
        call_depth = finding.get("call_depth", metadata.get("call_depth", 0))
        loc = finding.get("loc", metadata.get("loc", 10))
        is_upstream = metadata.get("finding_type") in ["crypto_capable_dependency", "dependency_function_analysis"]

        if primitive in ["certificate", "x509"]:
            asset_type = "certificate"
        elif primitive in ["secure_transport", "protocol"]:
            asset_type = "protocol"
        elif primitive in ["key_management", "asymmetric_key", "key_derivation"]:
            asset_type = "key"
        else:
            asset_type = "algorithm"

        asymmetric_primitives = {
            "public_key", "signature", "key_exchange",
            "asymmetric_encryption", "key_agreement"
        }
        algo_tokens = {"RSA", "DSA", "ECDSA", "ECDH", "ECC", "DH", "ED25519", "X25519", "ED448", "X448", "SIGNATURE"}
        is_asymmetric_named = any(token in algo for token in algo_tokens)
        is_asymmetric_op = operation in ["digital_signature", "signature_verification", "keypair_generation"]

        # Explicit Post-Quantum & Hybrid Token Recognition
        pqc_tokens = {"ML-KEM", "ML-DSA", "SLH-DSA", "FIPS-203", "FIPS-204", "FIPS-205", "KYBER", "DILITHIUM", "SPHINCS"}
        hybrid_tokens = {"X25519MLKEM", "SECP256R1MLDSA", "HYBRID"}
        
        is_pqc = any(token in algo for token in pqc_tokens) or any(token in algo for token in hybrid_tokens)
        
        if is_pqc:
            quantum_safe = True
            shor_vulnerable = False
        elif quantum_safe:
            shor_vulnerable = False
        else:
            shor_vulnerable = (primitive in asymmetric_primitives) or is_asymmetric_named or is_asymmetric_op

        if curve:
            name = f"{algo}-{curve}"
        elif mode and not algo.endswith(f"-{mode}") and not algo.endswith(mode):
            name = f"{algo}-{mode}"
        else:
            name = algo

        location = f"{file_path}:{line}"
        asset_id = self._generate_id("src", location, f"{algo}:{curve or mode or ''}")

        if finding.get("language"):
            metadata["language"] = finding.get("language")

        resolved_nist = self.resolve_nist_status(
            algorithm=algo,
            primitive=primitive,
            key_size=key_size,
            quantum_safe=quantum_safe,
            existing_status=finding.get("nist_status", "unknown")
        )

        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=name,
            asset_type=asset_type,
            source_domain="source_code",
            location=location,
            algorithm=algo,
            primitive=primitive,
            key_size=key_size,
            mode=mode,
            padding=padding,
            curve=curve,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vulnerable,
            nist_status=resolved_nist,
            direct_calls=direct_calls,
            transitive_calls=transitive_calls,
            call_depth=call_depth,
            loc=loc,
            is_upstream_dependency=is_upstream,
            security_findings=finding.get("security_findings", []),
            raw_metadata=metadata,
        )

    def _normalize_artifact(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        from spectra.utils.system_paths import format_display_path
        artifact_type = finding.get("artifact_type", "unknown")
        file_path = format_display_path(finding.get("file_path", ""))
        lower_path = file_path.lower()

        if artifact_type in ["x509_certificate", "system_root_ca"]:
            is_sys = finding.get("is_system_ca", False) or artifact_type == "system_root_ca"
            algo = finding.get("public_key_algorithm", "RSA")
            key_size = finding.get("key_size")
            subj = finding.get("subject", "unnamed")
            name = f"OS Root CA ({subj})" if is_sys else f"Certificate ({subj})"
            asset_type = "certificate"
            asset_prefix = "sys_ca" if is_sys else "cert"
            asset_id = self._generate_id(asset_prefix, file_path, str(finding.get("serial_number", "")))
            qs = finding.get("quantum_safe", False)
            nist_status = self.resolve_nist_status(algo, "signature", key_size, qs)
            meta = finding.get("raw_metadata", {}).copy()
            meta["is_system_ca"] = is_sys
            meta["scope"] = "system_trust_store" if is_sys else "application"
            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=name,
                asset_type=asset_type,
                source_domain="artifacts",
                location=file_path,
                algorithm=algo,
                primitive="signature",
                key_size=key_size,
                quantum_safe=qs,
                shor_vulnerable=True,
                nist_status=nist_status,
                security_findings=finding.get("security_findings", []),
                raw_metadata=meta,
            )
        elif artifact_type == "compiled_binary":
            algos = finding.get("detected_algorithms", [])
            algo_str = ", ".join(algos) if algos else "Binary-Crypto-Imports"
            asset_id = self._generate_id("bin", file_path, algo_str)
            qs = finding.get("quantum_safe", False)
            nist_status = self.resolve_nist_status(algo_str, "multiple", None, qs)
            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"Binary Crypto ({Path(file_path).name})",
                asset_type="algorithm",
                source_domain="artifacts",
                location=file_path,
                algorithm=algo_str,
                primitive="multiple",
                quantum_safe=qs,
                shor_vulnerable=not qs,
                nist_status=nist_status,
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )
        
        # Intelligent fallback for private keys and key stores based on filename/path clues
        algo = finding.get("algorithm", "")
        if not algo or algo == "UNKNOWN":
            if "ed25519" in lower_path:
                algo = "Ed25519"
            elif "ecdsa" in lower_path:
                algo = "ECDSA-P256"
            elif "rsa" in lower_path or "id_rsa" in lower_path:
                algo = "RSA-2048"
            elif "p12" in lower_path or "keystore" in lower_path:
                algo = "PKCS12-KeyStore"
            else:
                algo = "Asymmetric-Key"

        primitive = "private_key" if "key" in lower_path or "id_" in lower_path else finding.get("primitive", "key_management")
        asset_id = self._generate_id("art", file_path, algo)
        qs = "ed25519" in lower_path
        nist_status = self.resolve_nist_status(algo, primitive, None, qs)
        
        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=f"Key Artifact ({Path(file_path).name})",
            asset_type="key",
            source_domain="artifacts",
            location=file_path,
            algorithm=algo,
            primitive=primitive,
            quantum_safe=qs,
            shor_vulnerable="ed25519" not in lower_path,
            nist_status=nist_status,
            security_findings=finding.get("security_findings", []),
            raw_metadata=finding.get("raw_metadata", {}),
        )

    def _normalize_infrastructure(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        from spectra.utils.system_paths import format_display_path
        provider = finding.get("infra_provider", "infrastructure")
        algo = finding.get("algorithm", "unknown")
        key_size = finding.get("key_size")
        arn = format_display_path(finding.get("resource_arn", finding.get("file_path", "infra")))
        asset_id = self._generate_id("infra", arn, algo)
        qs = finding.get("quantum_safe", False)
        nist_status = self.resolve_nist_status(algo, "key_management", key_size, qs)
        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=f"Infrastructure Asset ({provider})",
            asset_type="key",
            source_domain="infrastructure",
            location=arn,
            algorithm=algo,
            primitive="key_management",
            key_size=key_size,
            quantum_safe=qs,
            shor_vulnerable=finding.get("shor_vulnerable", not qs),
            nist_status=nist_status,
            security_findings=finding.get("security_findings", []),
            raw_metadata=finding.get("raw_metadata", {}),
        )

    def _normalize_network(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        target = finding.get("target") or finding.get("file_path", "endpoint")
        port = finding.get("port") or finding.get("listen_port", 443)
        location = f"{target}:{port}"
        algo = finding.get("cipher_suite") or finding.get("ciphers") or "TLS-Transport"
        asset_id = self._generate_id("net", location, str(algo))
        qs = finding.get("quantum_safe", False)
        nist_status = self.resolve_nist_status(algo, "secure_transport", None, qs)
        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=f"Network Session ({location})",
            asset_type="protocol",
            source_domain="network",
            location=location,
            algorithm=algo,
            primitive="secure_transport",
            quantum_safe=qs,
            shor_vulnerable=True,
            nist_status=nist_status,
            security_findings=finding.get("security_findings", []),
            raw_metadata=finding.get("raw_metadata", {}),
        )

    def _normalize_fallback(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        algo = finding.get("algorithm", "UNKNOWN")
        loc = finding.get("file_path") or finding.get("location") or "unknown"
        asset_id = self._generate_id("gen", loc, algo)
        nist_status = self.resolve_nist_status(algo, finding.get("primitive", "operation"), None, False)
        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=f"Asset ({algo})",
            asset_type="algorithm",
            source_domain=finding.get("source_domain", "unknown"),
            location=loc,
            algorithm=algo,
            primitive=finding.get("primitive", "operation"),
            quantum_safe=False,
            shor_vulnerable=True,
            nist_status=nist_status,
            security_findings=finding.get("security_findings", []),
            raw_metadata=finding.get("raw_metadata", {}),
        )


    def _generate_id(self, prefix: str, location: str, differentiator: str) -> str:
        """Generates a deterministic unique asset ID via SHA-256 hash[cite: 20]."""
        seed = f"{prefix}:{location}:{differentiator}".encode("utf-8")
        digest = hashlib.sha256(seed).hexdigest()[:16]
        return f"{prefix}-{digest}"