"""
spectra.scanners.source.go_scanner
==================================
Go source code cryptographic scanner.
Inspects crypto/* standard library packages, golang.org/x/crypto, PQC modules,
and CodeQL Layer 3 crypto API extraction targets (X.509, TLS listeners, Sign/Verify).
"""

from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# 1. Standard crypto calls: aes.NewCipher, des.NewCipher, rc4.NewCipher
GO_CIPHER_REGEX = re.compile(
    r'\b(?P<pkg>aes|des|rc4)\.(?P<method>NewCipher|NewTripleDESCipher)\s*\(',
    re.IGNORECASE
)

# 2. Block cipher mode constructors: cipher.NewGCM, cipher.NewCBCEncrypter, cipher.NewCTR
GO_MODE_REGEX = re.compile(
    r'\bcipher\.(?P<mode>NewGCM|NewCBCEncrypter|NewCBCDecrypter|NewCTR|NewCFBEncrypter|NewOFB)\s*\(',
    re.IGNORECASE
)

# 3. RSA Key Generation with explicit key size: rsa.GenerateKey(rand.Reader, 1024)
GO_RSA_REGEX = re.compile(
    r'\brsa\.GenerateKey\s*\(\s*[^,]+,\s*(?P<size>\d+)\s*\)',
    re.IGNORECASE
)

# 4. Asymmetric ECDSA, Ed25519, and ECDH generators
GO_ASYMM_KEYGEN_REGEX = re.compile(
    r'\b(?P<pkg>ecdsa|ed25519|ecdh)\.(?P<method>GenerateKey|P256|P384|P521|X25519)\s*\(',
    re.IGNORECASE
)

# 5. Elliptic curve references: elliptic.P256(), elliptic.P384(), elliptic.P521()
GO_CURVE_REGEX = re.compile(
    r'\belliptic\.(?P<curve>P224|P256|P384|P521)\s*\(\s*\)',
    re.IGNORECASE
)

# 6. Hash & MAC calls: sha256.New(), md5.New(), hmac.New(...)
GO_HASH_REGEX = re.compile(
    r'\b(?P<pkg>sha256|sha512|sha1|md5|hmac)\.(?P<method>New|New224|New384)\s*\(',
    re.IGNORECASE
)

# 7. CodeQL Target: Digital Signatures & Verifications (Sign / Verify methods)
GO_SIGN_VERIFY_REGEX = re.compile(
    r'\b(?P<pkg>rsa|ecdsa|ed25519)\.(?P<method>SignPKCS1v15|VerifyPKCS1v15|SignPSS|VerifyPSS|SignASN1|VerifyASN1|Sign|Verify)\s*\(',
    re.IGNORECASE
)

# 8. CodeQL Target: X.509 Certificate and KeyPair operations
GO_X509_REGEX = re.compile(
    r'\b(?:x509\.(?P<x509_method>ParseCertificate|ParseCertificates|ParsePKIXPublicKey|ParsePKCS1PrivateKey|ParsePKCS8PrivateKey)|'
    r'tls\.(?P<tls_load>LoadX509KeyPair|X509KeyPair))\s*\(',
    re.IGNORECASE
)

# 9. CodeQL Target: TLS Listeners & Server Bindings (tls.Listen, tls.Server, tls.Client)
GO_TLS_NETWORK_REGEX = re.compile(
    r'\btls\.(?P<method>Listen|Server|Client|Dial|NewListener)\s*\(',
    re.IGNORECASE
)

# 10. TLS Version configurations: MinVersion: tls.VersionTLS10, tls.VersionSSL30, etc.
GO_TLS_VERSION_REGEX = re.compile(
    r'\b(?:MinVersion|MaxVersion)\s*:\s*tls\.(?P<ver>VersionSSL30|VersionTLS10|VersionTLS11|VersionTLS12|VersionTLS13)\b',
    re.IGNORECASE
)

# 11. CodeQL Target: Symmetric AEAD operational calls (gcm.Seal, gcm.Open)
GO_CIPHER_OP_REGEX = re.compile(
    r'\b(?P<receiver>[a-zA-Z0-9_]+)\.(?P<op>Seal|Open|CryptBlocks)\s*\(',
    re.IGNORECASE
)

# 12. Extended x/crypto calls: chacha20poly1305.New, secretbox.Seal, curve25519.X25519, sha3.New256
GO_XCRYPTO_REGEX = re.compile(
    r'\b(?P<mod>chacha20poly1305|secretbox|curve25519|sha3|argon2)\.(?P<func>New|Seal|Open|X25519|New256|New512|IDKey)\s*\(',
    re.IGNORECASE
)

# 13. Cloudflare CIRCL PQC Keygens: kyber768.GenerateKeyPair(), dilithium.GenerateKey(), sphincs.GenerateKey()
GO_PQC_REGEX = re.compile(
    r'\b(?P<algo>kyber\d+|dilithium|sphincs)\.(?P<method>GenerateKey(?:Pair)?)\s*\(',
    re.IGNORECASE
)

# 14. Insecure Math/Rand vs Secure Crypto/Rand
GO_RANDOM_REGEX = re.compile(
    r'\b(?P<mod>math/rand|crypto/rand)\.(?P<func>Read|Int|Intn)\b|\brand\.(?P<bare>Read|Int|Intn)\s*\(',
    re.IGNORECASE
)


class GoScanner(BaseSourceScanner):
    """Scanner for Go source files (.go)[cite: 66]."""

    def supported_extensions(self) -> List[str]:
        return [".go"]

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
        for match in GO_CIPHER_REGEX.finditer(content):
            pkg = match.group("pkg").lower()
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_cipher(file_path, line_idx, match.start(), pkg, method)
            if finding:
                _add_finding(finding, method)

        # 2. Block Cipher Modes
        for match in GO_MODE_REGEX.finditer(content):
            mode_ctor = match.group("mode")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_mode(file_path, line_idx, match.start(), mode_ctor)
            if finding:
                _add_finding(finding, mode_ctor)

        # 3. RSA Keygen & Key Sizes
        for match in GO_RSA_REGEX.finditer(content):
            key_size = int(match.group("size"))
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_rsa_keygen(file_path, line_idx, match.start(), key_size)
            if finding:
                _add_finding(finding, "GenerateKey")

        # 4. Asymmetric Curves & Keygens
        for match in GO_ASYMM_KEYGEN_REGEX.finditer(content):
            pkg = match.group("pkg").lower()
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_asymm_keygen(file_path, line_idx, match.start(), pkg, method)
            if finding:
                _add_finding(finding, method)

        # 5. Elliptic Curve references
        for match in GO_CURVE_REGEX.finditer(content):
            curve_raw = match.group("curve")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_curve(file_path, line_idx, match.start(), curve_raw)
            if finding:
                _add_finding(finding, curve_raw)

        # 6. Hashes & MAC
        for match in GO_HASH_REGEX.finditer(content):
            pkg = match.group("pkg").lower()
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_hash(file_path, line_idx, match.start(), pkg, method)
            if finding:
                _add_finding(finding, method)

        # 7. CodeQL Target: Digital Signatures (Sign / Verify)
        for match in GO_SIGN_VERIFY_REGEX.finditer(content):
            pkg = match.group("pkg").lower()
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_sign_verify(file_path, line_idx, match.start(), pkg, method)
            if finding:
                _add_finding(finding, method)

        # 8. CodeQL Target: X.509 Certificates & Key Material Loading
        for match in GO_X509_REGEX.finditer(content):
            x509_method = match.group("x509_method")
            tls_load = match.group("tls_load")
            sym = x509_method or tls_load
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_x509(file_path, line_idx, match.start(), sym)
            if finding:
                _add_finding(finding, sym)

        # 9. CodeQL Target: TLS Network Listeners & Servers
        for match in GO_TLS_NETWORK_REGEX.finditer(content):
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_tls_network(file_path, line_idx, match.start(), method)
            if finding:
                _add_finding(finding, method)

        # 10. TLS Version Configuration
        for match in GO_TLS_VERSION_REGEX.finditer(content):
            ver_name = match.group("ver")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_tls_version(file_path, line_idx, match.start(), ver_name)
            if finding:
                _add_finding(finding, "MinVersion")

        # 11. CodeQL Target: Operational Cryptographic Execution (Seal, Open)
        for match in GO_CIPHER_OP_REGEX.finditer(content):
            receiver = match.group("receiver")
            op = match.group("op")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_cipher_op(file_path, line_idx, match.start(), receiver, op)
            if finding:
                _add_finding(finding, op)

        # 12. Extended x/crypto
        for match in GO_XCRYPTO_REGEX.finditer(content):
            mod = match.group("mod").lower()
            func = match.group("func")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_xcrypto(file_path, line_idx, match.start(), mod, func)
            if finding:
                _add_finding(finding, func)

        # 13. Cloudflare CIRCL (PQC)
        for match in GO_PQC_REGEX.finditer(content):
            algo = match.group("algo").lower()
            method = match.group("method")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_pqc(file_path, line_idx, match.start(), algo, method)
            if finding:
                _add_finding(finding, method)

        # 14. Randomness
        for match in GO_RANDOM_REGEX.finditer(content):
            match_str = match.group(0)
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_random(file_path, line_idx, match.start(), match_str)
            if finding:
                _add_finding(finding, "Read")

        return findings

    def _process_cipher(self, file_path: Path, line_idx: int, col: int, pkg: str, method: str) -> SourceFinding:
        if method == "NewTripleDESCipher":
            algo_id = "ALGO-3DES"
        elif pkg == "des":
            algo_id = "ALGO-DES"
        elif pkg == "rc4":
            algo_id = "ALGO-RC4"
        else:
            algo_id = "ALGO-AES"

        algo_rule = self.rule_engine.algorithms.get(algo_id)
        sec_findings = []
        if algo_id in ["ALGO-DES", "ALGO-3DES", "ALGO-RC4"]:
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic cipher used: {algo_rule.name if algo_rule else algo_id}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="symmetric_cipher",
            algorithm=algo_rule.name if algo_rule else pkg.upper(),
            operation="symmetric_cipher_init",
            quantum_safe=algo_rule.quantum_safe if algo_rule else False,
            nist_status=algo_rule.nist_status if algo_rule else "unknown",
            security_findings=sec_findings,
            raw_metadata={"go_call": f"{pkg}.{method}"}
        )

    def _process_mode(self, file_path: Path, line_idx: int, col: int, mode_ctor: str) -> SourceFinding:
        mode_map = {
            "NewGCM": ("GCM", "aead_init"),
            "NewCBCEncrypter": ("CBC", "encryption_init"),
            "NewCBCDecrypter": ("CBC", "decryption_init"),
            "NewCTR": ("CTR", "stream_init"),
            "NewCFBEncrypter": ("CFB", "encryption_init"),
            "NewOFB": ("OFB", "stream_init")
        }
        mode_name, op_name = mode_map.get(mode_ctor, ("UNKNOWN", "operation"))
        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="symmetric_cipher",
            algorithm="BlockCipherMode",
            mode=mode_name,
            operation=op_name,
            quantum_safe=False,
            nist_status="operational",
            security_findings=[],
            raw_metadata={"constructor": mode_ctor}
        )

    def _process_rsa_keygen(self, file_path: Path, line_idx: int, col: int, key_size: int) -> SourceFinding:
        sec_findings = []
        if key_size < 2048:
            sec_findings.append({
                "issue": f"Key size ({key_size} bits) is below the minimum recommended threshold (2048 bits)",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="public_key",
            algorithm="RSA",
            key_size=key_size,
            operation="keypair_generation",
            quantum_safe=False,
            nist_status="deprecated_pqc",
            security_findings=sec_findings,
            raw_metadata={"key_size": key_size}
        )

    def _process_asymm_keygen(self, file_path: Path, line_idx: int, col: int, pkg: str, method: str) -> SourceFinding:
        mapping = {
            "ecdsa": ("ECDSA", "signature", "keypair_generation", None, False),
            "ed25519": ("Ed25519", "signature", "keypair_generation", "Ed25519", False),
            "ecdh": ("ECDH", "key_exchange", "key_agreement_init", self._resolve_curve_name(method), False)
        }
        algo_name, prim, op, curve, q_safe = mapping.get(pkg, ("Asymmetric", "public_key", "key_generation", None, False))

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo_name,
            curve=curve,
            operation=op,
            quantum_safe=q_safe,
            nist_status="deprecated_pqc",
            security_findings=[],
            raw_metadata={"pkg": pkg, "method": method}
        )

    def _process_curve(self, file_path: Path, line_idx: int, col: int, curve_raw: str) -> SourceFinding:
        curve_name = f"NIST-{curve_raw}"
        sec_findings = []
        if curve_raw == "P224":
            sec_findings.append({
                "issue": "Insecure or legacy elliptic curve specified: P224",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="public_key",
            algorithm="ECC",
            curve=curve_name,
            operation="curve_parameter_reference",
            quantum_safe=False,
            nist_status="deprecated_pqc",
            security_findings=sec_findings,
            raw_metadata={"curve": curve_raw}
        )

    def _process_hash(self, file_path: Path, line_idx: int, col: int, pkg: str, method: str) -> SourceFinding:
        algo_map = {
            "sha256": ("SHA-256", "hash", False),
            "sha512": ("SHA-512", "hash", False),
            "sha1": ("SHA-1", "hash", True),
            "md5": ("MD5", "hash", True),
            "hmac": ("HMAC", "mac", False)
        }
        algo_name, prim, is_insecure = algo_map.get(pkg, ("Hash", "hash", False))

        sec_findings = []
        if is_insecure:
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic hash function used: {algo_name}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo_name,
            operation="digest_computation" if prim == "hash" else "mac_computation",
            quantum_safe=not is_insecure,
            nist_status="broken_classical" if is_insecure else "approved",
            security_findings=sec_findings,
            raw_metadata={"hash_pkg": pkg}
        )

    def _process_sign_verify(self, file_path: Path, line_idx: int, col: int, pkg: str, method: str) -> SourceFinding:
        algo_map = {
            "rsa": ("RSA", None),
            "ecdsa": ("ECDSA", None),
            "ed25519": ("Ed25519", "Ed25519")
        }
        algo_name, curve = algo_map.get(pkg, (pkg.upper(), None))
        is_sign = "Sign" in method
        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="signature",
            algorithm=algo_name,
            curve=curve,
            operation="digital_signature" if is_sign else "signature_verification",
            quantum_safe=False,
            nist_status="deprecated_pqc",
            security_findings=[],
            raw_metadata={"signature_call": f"{pkg}.{method}"}
        )

    def _process_x509(self, file_path: Path, line_idx: int, col: int, method_name: str) -> SourceFinding:
        is_load = "Load" in method_name or "KeyPair" in method_name
        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="key_management" if is_load else "certificate",
            algorithm="X.509",
            operation="load_keypair" if is_load else "certificate_parsing",
            quantum_safe=False,
            nist_status="approved",
            security_findings=[],
            raw_metadata={"x509_call": method_name}
        )

    def _process_tls_network(self, file_path: Path, line_idx: int, col: int, method_name: str) -> SourceFinding:
        op_map = {
            "Listen": "tls_server_listen",
            "Server": "tls_server_init",
            "Client": "tls_client_init",
            "Dial": "tls_client_dial",
            "NewListener": "tls_listener_init"
        }
        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="secure_transport",
            algorithm="TLS",
            operation=op_map.get(method_name, "tls_network_init"),
            quantum_safe=False,
            nist_status="approved",
            security_findings=[],
            raw_metadata={"tls_network_call": f"tls.{method_name}"}
        )

    def _process_cipher_op(self, file_path: Path, line_idx: int, col: int, receiver: str, op: str) -> SourceFinding:
        op_map = {
            "Seal": "aead_encryption",
            "Open": "aead_decryption",
            "CryptBlocks": "block_cipher_execution"
        }
        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="symmetric_cipher",
            algorithm="AEAD_or_Cipher",
            operation=op_map.get(op, "cipher_execution"),
            quantum_safe=False,
            nist_status="operational",
            security_findings=[],
            raw_metadata={"receiver": receiver, "operation": op}
        )

    def _process_tls_version(self, file_path: Path, line_idx: int, col: int, ver_name: str) -> SourceFinding:
        sec_findings = []
        if ver_name in ["VersionSSL30", "VersionTLS10", "VersionTLS11"]:
            sec_findings.append({
                "issue": f"Deprecated and insecure TLS/SSL protocol version configured: {ver_name}",
                "severity": "CRITICAL"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="secure_transport",
            algorithm="TLS",
            operation="tls_configuration",
            quantum_safe=False,
            nist_status="approved" if "13" in ver_name or "12" in ver_name else "broken_classical",
            security_findings=sec_findings,
            raw_metadata={"tls_version": ver_name}
        )

    def _process_xcrypto(self, file_path: Path, line_idx: int, col: int, mod: str, func: str) -> SourceFinding:
        mapping = {
            "chacha20poly1305": ("ChaCha20-Poly1305", "symmetric_cipher", None, True),
            "secretbox": ("XSalsa20-Poly1305", "symmetric_cipher", None, True),
            "curve25519": ("X25519", "key_exchange", "X25519", False),
            "sha3": ("SHA-3", "hash", None, True),
            "argon2": ("Argon2", "key_derivation", None, True)
        }
        algo_name, prim, curve, q_safe = mapping.get(mod, (mod.upper(), "cryptographic_operation", None, False))

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo_name,
            curve=curve,
            operation="extended_crypto_call",
            quantum_safe=q_safe,
            nist_status="approved",
            security_findings=[],
            raw_metadata={"x_module": mod, "func": func}
        )

    def _process_pqc(self, file_path: Path, line_idx: int, col: int, algo: str, method: str) -> SourceFinding:
        if "kyber" in algo:
            canonical = "ML-KEM"
            prim = "key_encapsulation"
        elif "dilithium" in algo:
            canonical = "ML-DSA"
            prim = "signature"
        elif "sphincs" in algo:
            canonical = "SLH-DSA"
            prim = "signature"
        else:
            canonical = algo.upper()
            prim = "signature"

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=canonical,
            operation="keypair_generation",
            quantum_safe=True,
            nist_status="fips_pqc_standard",
            security_findings=[],
            raw_metadata={"pqc_call": f"{algo}.{method}"}
        )

    def _process_random(self, file_path: Path, line_idx: int, col: int, match_str: str) -> SourceFinding:
        is_math_rand = "math" in match_str
        snippet = self.extract_snippet(file_path, line_idx)

        sec_findings = []
        if is_math_rand:
            sec_findings.append({
                "issue": "Non-cryptographic PRNG (math/rand) used in source code",
                "severity": "HIGH"
            })

        return SourceFinding(
            source_domain="source_code",
            language="go",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="prng",
            algorithm="math.rand" if is_math_rand else "CSPRNG",
            operation="insecure_random" if is_math_rand else "secure_random",
            quantum_safe=not is_math_rand,
            nist_status="broken_classical" if is_math_rand else "approved",
            security_findings=sec_findings,
            raw_metadata={"random_call": match_str}
        )

    def _resolve_curve_name(self, method: str) -> str:
        mapping = {
            "P256": "NIST-P256",
            "P384": "NIST-P384",
            "P521": "NIST-P521",
            "X25519": "X25519"
        }
        return mapping.get(method, method)

    def _offset_to_line(self, content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1