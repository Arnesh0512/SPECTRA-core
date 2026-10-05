"""
spectra.scanners.source.rust_scanner
====================================
Rust source code cryptographic scanner.
Inspects ring, RustCrypto (aes-gcm, rsa, ecc), rustls, and pqcrypto crates,
incorporating CodeQL Layer 3 targets (PKCS#8, TLS defaults, Sign/Verify/Encrypt/Decrypt).
"""

from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# 1. Ciphers and AEAD Constructors (Aes256Gcm::new, ChaCha20Poly1305::new)
RUST_CIPHER_REGEX = re.compile(
    r'\b(?P<class>Aes128Gcm|Aes256Gcm|ChaCha20Poly1305|Des|Rc4)::(?P<method>new|new_from_slice)\s*\(',
    re.IGNORECASE
)

# 2. Ring Constants: handles both ring::aead::AES_256_GCM and bare imported constants like AES_256_GCM
RING_BARE_CONST_REGEX = re.compile(
    r'\b(?P<const>AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305|X25519|ECDH_P256|ECDH_P384|ED25519|RSA_PKCS1_[A-Z0-9_]+|SHA256|SHA384|SHA512)\b'
)

# 3. RSA Key Generation with explicit bits: RsaPrivateKey::new(&mut rng, 1024)
RUST_RSA_KEYGEN_REGEX = re.compile(
    r'\bRsaPrivateKey::(?:new|generate)\s*\(\s*[^,]+,\s*(?P<bits>\d+)\s*\)',
    re.IGNORECASE
)

# 4. CodeQL Target: Key Deserialization from PKCS#8
RUST_PKCS8_REGEX = re.compile(
    r'\b(?P<type>[a-zA-Z0-9_]+)::(?P<method>from_pkcs8_pem|from_pkcs8_der)\s*\(',
    re.IGNORECASE
)

# 5. RustCrypto & Dalek Elliptic Curves (p256, p384, k256, ed25519_dalek, x25519_dalek)
RUST_ECC_REGEX = re.compile(
    r'\b(?P<target>P256Key|P384Key|Secp256k1Key|p256::SecretKey|p384::SecretKey|k256::SecretKey|SigningKey|VerifyingKey)::(?P<method>random|generate|new|from_bytes)\s*\(',
    re.IGNORECASE
)

# 6. Hashes (Sha256::new, Md5::new, Sha1::new)
RUST_HASH_REGEX = re.compile(
    r'\b(?P<hash>Sha224|Sha256|Sha384|Sha512|Md5|Sha1)::new\s*\(\s*\)',
    re.IGNORECASE
)

# 7. CodeQL Target: Rustls Configuration (with_safe_defaults, bind)
RUST_TLS_REGEX = re.compile(
    r'\b(?P<target>[a-zA-Z0-9_]+)\.(?P<method>with_safe_defaults|bind)\s*\(',
    re.IGNORECASE
)

# 8. CodeQL Target: Direct Operational Calls (encrypt, decrypt, sign, verify)
RUST_OP_EXEC_REGEX = re.compile(
    r'\b(?P<receiver>[a-zA-Z0-9_]+)\.(?P<method>encrypt|decrypt|sign|verify)\s*\(',
    re.IGNORECASE
)

# 9. Post-Quantum Cryptography (kyber768::keypair, dilithium3::keypair, sphincsplus::keypair)
RUST_PQC_REGEX = re.compile(
    r'\b(?P<pqc>kyber\d*|dilithium\d*|sphincsplus|falcon\d*)::(?P<method>keypair|encapsulate|decapsulate|sign|verify)\s*\(',
    re.IGNORECASE
)

# 10. Randomness: Standalone assignment or instantiation (let ... = OsRng / thread_rng)
RUST_RANDOM_REGEX = re.compile(
    r'(?:=\s*|\breturn\s+)(?:rand::)?(?:rngs::)?(?P<type>OsRng|thread_rng\(\)|thread_rng)\b'
)

# 11. Extended Rust Ecosystem: hkdf, bcrypt, argon2, x509_parser, webpki, openssl
RUST_EXT_ECOSYSTEM_REGEX = re.compile(
    r'\b(?P<crate>Hkdf|bcrypt|Argon2|x509_parser|EndEntityCert|openssl::(?:symm|rsa|ssl))::(?P<method>[a-zA-Z0-9_]+)\b'
)


class RustScanner(BaseSourceScanner):
    """Scanner for Rust source files (.rs)."""

    def supported_extensions(self) -> List[str]:
        return [".rs"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        def _add_finding(finding: SourceFinding, symbol_name: str) -> None:
            dirs, trans, depth = self.compute_call_metrics(file_path, symbol_name, line_number=finding.line_number)
            finding.direct_calls = dirs
            finding.transitive_calls = trans
            finding.call_depth = depth
            findings.append(finding)

        # 1. Symmetric Ciphers
        for match in RUST_CIPHER_REGEX.finditer(content):
            cls = match.group("class")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_cipher(file_path, line_idx, match.start(), cls, method)
            if finding:
                _add_finding(finding, method)

        # 2. Ring Bare/Full Constants
        for match in RING_BARE_CONST_REGEX.finditer(content):
            c_name = match.group("const")
            line_idx = self._offset_to_line(content, match.start())
            # Skip if part of an import block
            line = content.splitlines()[line_idx - 1]
            if line.strip().startswith("use "):
                continue
            res = self._process_ring_const_name(file_path, line_idx, match.start(), c_name)
            if res:
                _add_finding(res, c_name)

        # 3. RSA Keygen & Key Sizes
        for match in RUST_RSA_KEYGEN_REGEX.finditer(content):
            bits = int(match.group("bits"))
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_rsa_keygen(file_path, line_idx, match.start(), bits)
            if finding:
                _add_finding(finding, "new")

        # 4. CodeQL Target: PKCS#8 Deserialization
        for match in RUST_PKCS8_REGEX.finditer(content):
            type_name = match.group("type")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_pkcs8(file_path, line_idx, match.start(), type_name, method)
            if finding:
                _add_finding(finding, method)

        # 5. Elliptic Curves
        for match in RUST_ECC_REGEX.finditer(content):
            target = match.group("target")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_ecc_target(file_path, line_idx, match.start(), target, method)
            if finding:
                _add_finding(finding, method)

        # 6. Hashes
        for match in RUST_HASH_REGEX.finditer(content):
            h_name = match.group("hash")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_hash(file_path, line_idx, match.start(), h_name)
            if finding:
                _add_finding(finding, "new")

        # 7. CodeQL Target: Rustls Configuration (with_safe_defaults, bind)
        for match in RUST_TLS_REGEX.finditer(content):
            target = match.group("target")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_tls(file_path, line_idx, match.start(), target, method)
            if finding:
                _add_finding(finding, method)

        # 8. CodeQL Target: Direct Operational Calls (encrypt, decrypt, sign, verify)
        for match in RUST_OP_EXEC_REGEX.finditer(content):
            receiver = match.group("receiver")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_op_exec(file_path, line_idx, match.start(), receiver, method)
            if finding:
                _add_finding(finding, method)

        # 9. Post-Quantum Cryptography
        for match in RUST_PQC_REGEX.finditer(content):
            pqc_name = match.group("pqc")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_pqc_call(file_path, line_idx, match.start(), pqc_name, method)
            if finding:
                _add_finding(finding, method)

        # 10. Randomness
        for match in RUST_RANDOM_REGEX.finditer(content):
            rng_type = match.group("type")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_random(file_path, line_idx, match.start(), rng_type)
            if finding:
                _add_finding(finding, rng_type.replace("()", ""))

        # 11. Extended Rust Ecosystem
        for match in RUST_EXT_ECOSYSTEM_REGEX.finditer(content):
            crate = match.group("crate")
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            col = match.start()
            snippet = self.extract_snippet(file_path, line_idx)

            crate_lower = crate.lower()
            if "hkdf" in crate_lower:
                algo = "HKDF"
                prim = "key_derivation"
                op = "key_derivation"
                q_safe = True
            elif "bcrypt" in crate_lower:
                algo = "bcrypt"
                prim = "key_derivation"
                op = "password_hash"
                q_safe = False
            elif "argon2" in crate_lower:
                algo = "Argon2"
                prim = "key_derivation"
                op = "password_hash"
                q_safe = True
            elif "x509" in crate_lower or "endentitycert" in crate_lower:
                algo = "X.509"
                prim = "certificate"
                op = "certificate_parsing"
                q_safe = False
            elif "openssl::rsa" in crate_lower:
                algo = "RSA"
                prim = "public_key"
                op = "keypair_generation"
                q_safe = False
            elif "openssl::ssl" in crate_lower:
                algo = "TLS"
                prim = "secure_transport"
                op = "tls_context_init"
                q_safe = False
            else:
                algo = "AES"
                prim = "symmetric_cipher"
                op = "symmetric_cipher_init"
                q_safe = False

            rust_eco_finding = SourceFinding(
                source_domain="source_code",
                language="rust",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=col,
                code_snippet=snippet,
                primitive=prim,
                algorithm=algo,
                operation=op,
                quantum_safe=q_safe,
                nist_status="approved",
                security_findings=[],
                raw_metadata={"rust_ecosystem_call": f"{crate}::{method}"}
            )
            _add_finding(rust_eco_finding, method)

        return findings

    def _process_cipher(self, file_path: Path, line_idx: int, col: int, cls: str, method: str) -> SourceFinding:
        cls_lower = cls.lower()
        if "des" in cls_lower:
            algo_id = "ALGO-DES"
            prim = "symmetric_cipher"
        elif "rc4" in cls_lower:
            algo_id = "ALGO-RC4"
            prim = "symmetric_cipher"
        elif "chacha" in cls_lower:
            algo_id = "ALGO-CHACHA20-POLY1305"
            prim = "symmetric_cipher"
        else:
            algo_id = "ALGO-AES"
            prim = "symmetric_cipher"

        algo_rule = self.rule_engine.algorithms.get(algo_id)
        mode = "GCM" if "gcm" in cls_lower else None

        sec_findings = []
        if algo_id in ["ALGO-DES", "ALGO-RC4"]:
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic cipher used: {algo_rule.name if algo_rule else algo_id}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo_rule.name if algo_rule else cls,
            mode=mode,
            operation="aead_init" if mode else "symmetric_cipher_init",
            quantum_safe=algo_rule.quantum_safe if algo_rule else False,
            nist_status=algo_rule.nist_status if algo_rule else "unknown",
            security_findings=sec_findings,
            raw_metadata={"rust_call": f"{cls}::{method}"}
        )

    def _process_ring_const_name(self, file_path: Path, line_idx: int, col: int, c_name: str) -> Optional[SourceFinding]:
        snippet = self.extract_snippet(file_path, line_idx)
        curve = None
        mode = None

        if "GCM" in c_name:
            algo_id = "ALGO-AES"
            mode = "GCM"
            prim = "symmetric_cipher"
            op = "aead_init"
        elif "CHACHA20" in c_name:
            algo_id = "ALGO-CHACHA20-POLY1305"
            prim = "symmetric_cipher"
            op = "aead_init"
        elif c_name == "X25519":
            algo_id = "ALGO-X25519"
            curve = "X25519"
            prim = "key_exchange"
            op = "key_agreement_init"
        elif c_name == "ECDH_P256":
            algo_id = "ALGO-ECDH"
            curve = "NIST-P256"
            prim = "key_exchange"
            op = "key_agreement_init"
        elif c_name == "ECDH_P384":
            algo_id = "ALGO-ECDH"
            curve = "NIST-P384"
            prim = "key_exchange"
            op = "key_agreement_init"
        elif c_name == "ED25519":
            algo_id = "ALGO-ED25519"
            curve = "Ed25519"
            prim = "signature"
            op = "digital_signature"
        elif "RSA" in c_name:
            algo_id = "ALGO-RSA"
            prim = "signature"
            op = "digital_signature"
        elif c_name in ["SHA256", "SHA384", "SHA512"]:
            algo_id = f"ALGO-SHA2-{c_name.replace('SHA', '')}"
            prim = "hash"
            op = "digest_computation"
        else:
            return None

        algo_rule = self.rule_engine.algorithms.get(algo_id)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo_rule.name if algo_rule else c_name,
            mode=mode,
            curve=curve,
            operation=op,
            quantum_safe=algo_rule.quantum_safe if algo_rule else False,
            nist_status=algo_rule.nist_status if algo_rule else "unknown",
            security_findings=[],
            raw_metadata={"ring_const": c_name}
        )

    def _process_rsa_keygen(self, file_path: Path, line_idx: int, col: int, bits: int) -> SourceFinding:
        sec_findings = []
        if bits < 2048:
            sec_findings.append({
                "issue": f"Key size ({bits} bits) is below the minimum recommended threshold (2048 bits)",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="public_key",
            algorithm="RSA",
            key_size=bits,
            operation="keypair_generation",
            quantum_safe=False,
            nist_status="deprecated_pqc",
            security_findings=sec_findings,
            raw_metadata={"key_size": bits}
        )

    def _process_pkcs8(self, file_path: Path, line_idx: int, col: int, type_name: str, method: str) -> SourceFinding:
        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="key_management",
            algorithm="PKCS#8",
            operation=f"load_{method}",
            quantum_safe=False,
            nist_status="approved",
            security_findings=[],
            raw_metadata={"type": type_name, "method": method}
        )

    def _process_ecc_target(self, file_path: Path, line_idx: int, col: int, target: str, method: str) -> SourceFinding:
        t_clean = target.lower()
        if "p256" in t_clean:
            curve, algo, prim = "NIST-P256", "ECC", "public_key"
        elif "p384" in t_clean:
            curve, algo, prim = "NIST-P384", "ECC", "public_key"
        elif "secp256k1" in t_clean or "k256" in t_clean:
            curve, algo, prim = "secp256k1", "ECC", "public_key"
        elif "signingkey" in t_clean or "verifyingkey" in t_clean:
            curve, algo, prim = "Ed25519", "Ed25519", "signature"
        else:
            curve, algo, prim = "UnknownCurve", "ECC", "public_key"

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo,
            curve=curve,
            operation="keypair_generation",
            quantum_safe=False,
            nist_status="deprecated_pqc",
            security_findings=[],
            raw_metadata={"target": target, "method": method}
        )

    def _process_hash(self, file_path: Path, line_idx: int, col: int, h_name: str) -> SourceFinding:
        is_insecure = h_name.lower() in ["md5", "sha1"]
        sec_findings = []
        if is_insecure:
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic hash function used: {h_name}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="hash",
            algorithm=h_name.upper(),
            operation="digest_computation",
            quantum_safe=not is_insecure,
            nist_status="broken_classical" if is_insecure else "approved",
            security_findings=sec_findings,
            raw_metadata={"hash": h_name}
        )

    def _process_tls(self, file_path: Path, line_idx: int, col: int, target: str, method: str) -> SourceFinding:
        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="secure_transport",
            algorithm="TLS",
            operation="tls_configuration" if method == "with_safe_defaults" else "tls_server_bind",
            quantum_safe=False,
            nist_status="approved",
            security_findings=[],
            raw_metadata={"target": target, "method": method}
        )

    def _process_op_exec(self, file_path: Path, line_idx: int, col: int, receiver: str, method: str) -> SourceFinding:
        op_map = {
            "encrypt": ("symmetric_cipher", "encryption"),
            "decrypt": ("symmetric_cipher", "decryption"),
            "sign": ("signature", "digital_signature"),
            "verify": ("signature", "signature_verification")
        }
        prim, op = op_map.get(method, ("cryptographic_operation", method))
        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm="CryptoExecution",
            operation=op,
            quantum_safe=False,
            nist_status="operational",
            security_findings=[],
            raw_metadata={"receiver": receiver, "method": method}
        )

    def _process_pqc_call(self, file_path: Path, line_idx: int, col: int, pqc_name: str, method: str) -> SourceFinding:
        pqc_lower = pqc_name.lower()
        if "kyber" in pqc_lower:
            algo = "ML-KEM"
            prim = "key_encapsulation"
        elif "dilithium" in pqc_lower:
            algo = "ML-DSA"
            prim = "signature"
        elif "sphincs" in pqc_lower:
            algo = "SLH-DSA"
            prim = "signature"
        elif "falcon" in pqc_lower:
            algo = "Falcon"
            prim = "signature"
        else:
            algo = pqc_name.upper()
            prim = "key_encapsulation"

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo,
            operation="keypair_generation",
            quantum_safe=True,
            nist_status="fips_pqc_standard",
            security_findings=[],
            raw_metadata={"pqc": pqc_name, "method": method}
        )

    def _process_random(self, file_path: Path, line_idx: int, col: int, rng_type: str) -> SourceFinding:
        is_os_rng = "OsRng" in rng_type
        snippet = self.extract_snippet(file_path, line_idx)
        sec_findings = []
        if not is_os_rng:
            sec_findings.append({
                "issue": "Non-cryptographic or standard PRNG (thread_rng) detected",
                "severity": "LOW"
            })

        return SourceFinding(
            source_domain="source_code",
            language="rust",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="prng",
            algorithm="CSPRNG" if is_os_rng else "PRNG",
            operation="secure_random" if is_os_rng else "pseudorandom_generation",
            quantum_safe=is_os_rng,
            nist_status="approved" if is_os_rng else "operational",
            security_findings=sec_findings,
            raw_metadata={"rng": rng_type}
        )

    def _offset_to_line(self, content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1