"""
spectra.scanners.source.cpp_scanner
===================================
C and C++ source code cryptographic scanner.
Inspects OpenSSL (EVP, RSA, EC, X509, SSL/TLS, PKCS), BoringSSL, libsodium,
liboqs (PQC), and CodeQL Layer 3 crypto API extraction targets.
"""

from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# 1. OpenSSL EVP Cipher macros: EVP_aes_256_gcm(), EVP_des_ede3_cbc(), etc.
EVP_CIPHER_MACRO_REGEX = re.compile(
    r'\b(?P<func>EVP_(?:aes|des|rc4|chacha20)[a-z0-9_]*)\s*\(\s*\)',
    re.IGNORECASE
)

# 2. OpenSSL EVP Digest macros: EVP_sha256(), EVP_sha3_512(), EVP_md5(), etc.
EVP_MD_MACRO_REGEX = re.compile(
    r'\b(?P<func>EVP_(?:sha\d+|sha3_\d+|md5|ripemd\d*))\s*\(\s*\)',
    re.IGNORECASE
)

# 3. OpenSSL 3.0 Fetch API: EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL), EVP_MD_fetch(...)
OPENSSL3_FETCH_REGEX = re.compile(
    r'\b(?P<fetch>EVP_CIPHER_fetch|EVP_MD_fetch|EVP_KDF_fetch|EVP_MAC_fetch)\s*\(\s*[^,]+,\s*["\'](?P<algo>[^"\']+)["\']',
    re.IGNORECASE
)

# 4. OpenSSL RSA Key Generation: RSA_generate_key_ex(rsa, 1024, ...) or EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024)
RSA_KEYGEN_REGEX = re.compile(
    r'\b(?:RSA_generate_key_ex\s*\([^,]+,\s*(?P<bits1>\d+)|'
    r'EVP_PKEY_CTX_set_rsa_keygen_bits\s*\([^,]+,\s*(?P<bits2>\d+)|'
    r'EVP_PKEY_Q_keygen\s*\([^,]+,\s*[^,]+,\s*["\']RSA["\'],\s*(?P<bits3>\d+))\b',
    re.IGNORECASE
)

# 5. OpenSSL EC Curves: EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) or EC_GROUP_new_by_curve_name(...)
EC_CURVE_REGEX = re.compile(
    r'\b(?:EC_KEY_new_by_curve_name|EC_GROUP_new_by_curve_name)\s*\(\s*(?P<nid>NID_[a-zA-Z0-9_]+)\s*\)',
    re.IGNORECASE
)

# 6. Operational Lifecycles: EVP_EncryptInit_ex, EVP_DigestSignInit, HMAC_Init_ex, etc.
LIFECYCLE_REGEX = re.compile(
    r'\b(?P<op>EVP_EncryptInit_ex|EVP_DecryptInit_ex|EVP_DigestSignInit|EVP_DigestVerifyInit|HMAC_Init_ex)\s*\(',
    re.IGNORECASE
)

# 7. CodeQL isCryptoApi Target: OpenSSL (SSL|TLS|X509|PKCS5|PKCS12)_.*
CODEQL_EXT_C_REGEX = re.compile(
    r'\b(?P<func>(?:SSL|TLS|X509|PKCS5|PKCS12)_[a-zA-Z0-9_]+)\s*\(',
    re.IGNORECASE
)

# 8. Libsodium API calls (box, sign, secretbox, kx, auth)
SODIUM_REGEX = re.compile(
    r'\b(?P<call>crypto_box_keypair|crypto_sign_keypair|crypto_secretbox_easy|crypto_kx_keypair|crypto_auth)\s*\(',
    re.IGNORECASE
)

# 9. CodeQL isCryptoApi Target: Libsodium crypto_(aead|generichash).*
SODIUM_EXT_REGEX = re.compile(
    r'\b(?P<call>crypto_(?:aead|generichash)[a-zA-Z0-9_]*)\s*\(',
    re.IGNORECASE
)

# 10. Open Quantum Safe (liboqs): OQS_KEM_new("Kyber768"), OQS_SIG_new("Dilithium3")
OQS_PQC_REGEX = re.compile(
    r'\b(?P<func>OQS_KEM_new|OQS_SIG_new)\s*\(\s*["\'](?P<algo>[^"\']+)["\']\s*\)',
    re.IGNORECASE
)

# 11. CSPRNG (RAND_bytes, randombytes_buf) vs Insecure (rand, srand)
PRNG_REGEX = re.compile(
    r'\b(?P<func>RAND_bytes|RAND_priv_bytes|randombytes_buf|rand|srand)\s*\(',
    re.IGNORECASE
)

# 12. mbedTLS, wolfSSL, Botan, Crypto++ calls from ecosystem catalogs
EXT_CPP_CRYPTO_REGEX = re.compile(
    r'\b(?P<call>mbedtls_aes_[a-z0-9_]+|mbedtls_sha\d+|mbedtls_ssl_[a-z0-9_]+|'
    r'wolfSSL_[a-zA-Z0-9_]+|wc_AesGcm[a-zA-Z0-9_]*|'
    r'Botan::(?:Cipher_Mode::create|AutoSeeded_RNG)|'
    r'CryptoPP::(?:AES::Encryption|RSA::PrivateKey))\b',
    re.IGNORECASE
)


class CPPScanner(BaseSourceScanner):
    """Scanner for C and C++ source files (.c, .cpp, .cc, .cxx, .h, .hpp)."""

    def supported_extensions(self) -> List[str]:
        return [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        # Helper to enrich findings with computed call-graph metrics
        def _add_finding(finding: SourceFinding, symbol_name: str) -> None:
            dirs, trans, depth = self.compute_call_metrics(file_path, symbol_name, line_number=finding.line_number)
            finding.direct_calls = dirs
            finding.transitive_calls = trans
            finding.call_depth = depth
            findings.append(finding)

        # 1. OpenSSL EVP Cipher macros
        for match in EVP_CIPHER_MACRO_REGEX.finditer(content):
            func_name = match.group("func")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_cipher_macro(file_path, line_idx, match.start(), func_name)
            if finding:
                _add_finding(finding, func_name)

        # 2. OpenSSL EVP Digest macros
        for match in EVP_MD_MACRO_REGEX.finditer(content):
            func_name = match.group("func")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_digest_macro(file_path, line_idx, match.start(), func_name)
            if finding:
                _add_finding(finding, func_name)

        # 3. OpenSSL 3.0 Fetch API
        for match in OPENSSL3_FETCH_REGEX.finditer(content):
            fetch_func = match.group("fetch")
            algo_str = match.group("algo")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_fetch_call(file_path, line_idx, match.start(), fetch_func, algo_str)
            if finding:
                _add_finding(finding, fetch_func)

        # 4. RSA Key Generation & Key Size
        for match in RSA_KEYGEN_REGEX.finditer(content):
            bits = match.group("bits1") or match.group("bits2") or match.group("bits3")
            key_size = int(bits) if bits else 2048
            line_idx = self._offset_to_line(content, match.start())

            sec_findings = []
            if key_size < 2048:
                sec_findings.append({
                    "issue": f"Key size ({key_size} bits) is below the minimum recommended threshold (2048 bits)",
                    "severity": "HIGH"
                })

            snippet = self.extract_snippet(file_path, line_idx)
            rsa_finding = SourceFinding(
                source_domain="source_code",
                language="cpp",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
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
            _add_finding(rsa_finding, "RSA_generate_key_ex")

        # 5. OpenSSL EC Curves
        for match in EC_CURVE_REGEX.finditer(content):
            raw_nid = match.group("nid")
            line_idx = self._offset_to_line(content, match.start())
            canonical_curve = self._resolve_curve_nid(raw_nid)

            sec_findings = []
            if "192" in raw_nid or "160" in raw_nid:
                sec_findings.append({
                    "issue": f"Insecure or deprecated elliptic curve specified: {raw_nid}",
                    "severity": "HIGH"
                })

            snippet = self.extract_snippet(file_path, line_idx)
            ec_finding = SourceFinding(
                source_domain="source_code",
                language="cpp",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
                code_snippet=snippet,
                primitive="public_key",
                algorithm="ECC",
                curve=canonical_curve,
                operation="keypair_generation",
                quantum_safe=False,
                nist_status="deprecated_pqc",
                security_findings=sec_findings,
                raw_metadata={"nid": raw_nid}
            )
            _add_finding(ec_finding, "EC_KEY_new_by_curve_name")

        # 6. Operational Lifecycles
        for match in LIFECYCLE_REGEX.finditer(content):
            op_name = match.group("op")
            line_idx = self._offset_to_line(content, match.start())
            snippet = self.extract_snippet(file_path, line_idx)
            lifecycle_finding = SourceFinding(
                source_domain="source_code",
                language="cpp",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
                code_snippet=snippet,
                primitive="cryptographic_operation",
                algorithm=self._map_op_to_algo(op_name),
                operation=self._map_op_to_operation(op_name),
                quantum_safe=False,
                nist_status="operational",
                security_findings=[],
                raw_metadata={"operation": op_name}
            )
            _add_finding(lifecycle_finding, op_name)

        # 7. CodeQL isCryptoApi Target: SSL, TLS, X509, PKCS5, PKCS12
        for match in CODEQL_EXT_C_REGEX.finditer(content):
            func_name = match.group("func")
            line_idx = self._offset_to_line(content, match.start())
            col = match.start()
            snippet = self.extract_snippet(file_path, line_idx)

            sec_findings = []
            func_upper = func_name.upper()
            if any(weak in func_upper for weak in ["SSLV2", "SSLV3", "TLSV1_METHOD", "TLSV1_1_METHOD"]):
                sec_findings.append({
                    "issue": f"Deprecated and insecure TLS/SSL protocol method invoked: {func_name}",
                    "severity": "CRITICAL"
                })

            prim = "cryptographic_operation"
            algo = "SystemCrypto"
            op = "api_call"

            if func_upper.startswith("X509"):
                prim = "certificate"
                algo = "X.509"
                op = "certificate_parsing"
            elif func_upper.startswith("PKCS5"):
                prim = "key_derivation"
                algo = "PBKDF2"
                op = "key_derivation"
            elif func_upper.startswith("PKCS12"):
                prim = "key_management"
                algo = "PKCS#12"
                op = "keystore_load"
            elif func_upper.startswith("SSL") or func_upper.startswith("TLS"):
                prim = "secure_transport"
                algo = "TLS"
                op = "tls_session_init"

            codeql_finding = SourceFinding(
                source_domain="source_code",
                language="cpp",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=col,
                code_snippet=snippet,
                primitive=prim,
                algorithm=algo,
                operation=op,
                quantum_safe=False,
                nist_status="approved" if not sec_findings else "broken_classical",
                security_findings=sec_findings,
                raw_metadata={"codeql_c_api": func_name}
            )
            _add_finding(codeql_finding, func_name)

        # 8. Libsodium Core (box, sign, secretbox, kx, auth)
        for match in SODIUM_REGEX.finditer(content):
            call_name = match.group("call")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_sodium_call(file_path, line_idx, match.start(), call_name)
            if finding:
                _add_finding(finding, call_name)

        # 9. CodeQL isCryptoApi Target: Libsodium AEAD & GenericHash
        for match in SODIUM_EXT_REGEX.finditer(content):
            call_name = match.group("call")
            line_idx = self._offset_to_line(content, match.start())
            col = match.start()
            snippet = self.extract_snippet(file_path, line_idx)

            if "generichash" in call_name:
                algo = "BLAKE2b"
                prim = "hash"
                op = "digest_computation"
            else:
                algo = "ChaCha20-Poly1305"
                prim = "symmetric_cipher"
                op = "aead_encryption"

            sodium_ext_finding = SourceFinding(
                source_domain="source_code",
                language="cpp",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=col,
                code_snippet=snippet,
                primitive=prim,
                algorithm=algo,
                operation=op,
                quantum_safe=True,
                nist_status="approved",
                security_findings=[],
                raw_metadata={"sodium_call": call_name}
            )
            _add_finding(sodium_ext_finding, call_name)

        # 10. Liboqs Post-Quantum Cryptography
        for match in OQS_PQC_REGEX.finditer(content):
            func_name = match.group("func")
            algo_param = match.group("algo")
            line_idx = self._offset_to_line(content, match.start())
            finding = self._process_oqs_call(file_path, line_idx, match.start(), func_name, algo_param)
            if finding:
                _add_finding(finding, func_name)

        # 11. Randomness / PRNG
        for match in PRNG_REGEX.finditer(content):
            func_name = match.group("func")
            line_idx = self._offset_to_line(content, match.start())
            snippet = self.extract_snippet(file_path, line_idx)

            if func_name in ["rand", "srand"]:
                prng_finding = SourceFinding(
                    source_domain="source_code",
                    language="cpp",
                    file_path=str(file_path.resolve()),
                    line_number=line_idx,
                    column_number=match.start(),
                    code_snippet=snippet,
                    primitive="prng",
                    algorithm="rand",
                    operation="insecure_random",
                    quantum_safe=False,
                    nist_status="broken_classical",
                    security_findings=[{
                        "issue": "Non-cryptographic PRNG (rand/srand) used in security context",
                        "severity": "HIGH"
                    }],
                    raw_metadata={"function": func_name}
                )
                _add_finding(prng_finding, func_name)
            else:
                csprng_finding = SourceFinding(
                    source_domain="source_code",
                    language="cpp",
                    file_path=str(file_path.resolve()),
                    line_number=line_idx,
                    column_number=match.start(),
                    code_snippet=snippet,
                    primitive="prng",
                    algorithm="CSPRNG",
                    operation="secure_random",
                    quantum_safe=True,
                    nist_status="approved",
                    security_findings=[],
                    raw_metadata={"function": func_name}
                )
                _add_finding(csprng_finding, func_name)

        # 12. Extended C/C++ Ecosystem Libraries (mbedtls, wolfssl, botan, cryptopp)
        for match in EXT_CPP_CRYPTO_REGEX.finditer(content):
            call_name = match.group("call")
            line_idx = self._offset_to_line(content, match.start())
            col = match.start()
            snippet = self.extract_snippet(file_path, line_idx)

            sec_findings = []
            algo = "SystemCrypto"
            prim = "cryptographic_operation"
            op = "library_call"

            if "mbedtls_aes" in call_name.lower():
                algo = "AES"
                prim = "symmetric_cipher"
                op = "symmetric_cipher_init"
                if "ecb" in call_name.lower():
                    sec_findings.append({
                        "issue": f"Insecure ECB cipher mode invoked: {call_name}",
                        "severity": "CRITICAL"
                    })
            elif "mbedtls_sha256" in call_name.lower():
                algo = "SHA-256"
                prim = "hash"
                op = "digest_computation"
            elif "mbedtls_ssl" in call_name.lower() or "wolfssl" in call_name.lower():
                algo = "TLS"
                prim = "secure_transport"
                op = "tls_session_init"
            elif "wc_aesgcm" in call_name.lower() or "cryptopp::aes" in call_name.lower():
                algo = "AES"
                prim = "symmetric_cipher"
                op = "aead_encryption"
            elif "cryptopp::rsa" in call_name.lower():
                algo = "RSA"
                prim = "public_key"
                op = "keypair_generation"
            elif "botan::autoseeded_rng" in call_name.lower():
                algo = "CSPRNG"
                prim = "prng"
                op = "secure_random"

            ext_cpp_finding = SourceFinding(
                source_domain="source_code",
                language="cpp",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=col,
                code_snippet=snippet,
                primitive=prim,
                algorithm=algo,
                operation=op,
                quantum_safe=(algo in ["SHA-256", "CSPRNG"]),
                nist_status="approved" if not sec_findings else "broken_classical",
                security_findings=sec_findings,
                raw_metadata={"c_call": call_name}
            )
            _add_finding(ext_cpp_finding, call_name)

        return findings

    def _process_cipher_macro(self, file_path: Path, line_idx: int, col: int, func_name: str) -> SourceFinding:
        clean = func_name.replace("EVP_", "").lower()
        mode = None
        for m in ["ecb", "cbc", "gcm", "ctr", "cfb", "ofb"]:
            if m in clean:
                mode = m.upper()
                break

        algo_id = "ALGO-AES"
        if "des_ede3" in clean:
            algo_id = "ALGO-3DES"
        elif "des" in clean:
            algo_id = "ALGO-DES"
        elif "rc4" in clean:
            algo_id = "ALGO-RC4"
        elif "chacha20_poly1305" in clean:
            algo_id = "ALGO-CHACHA20-POLY1305"
        elif "chacha20" in clean:
            algo_id = "ALGO-CHACHA20"

        algo_rule = self.rule_engine.algorithms.get(algo_id)
        sec_findings = []
        if mode == "ECB":
            sec_findings.append({
                "issue": f"Insecure ECB cipher mode invoked via OpenSSL macro ({func_name})",
                "severity": "CRITICAL"
            })
        if algo_id in ["ALGO-DES", "ALGO-3DES", "ALGO-RC4"]:
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic algorithm invoked: {algo_rule.name if algo_rule else algo_id}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="cpp",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="symmetric_cipher",
            algorithm=algo_rule.name if algo_rule else "AES",
            mode=mode,
            operation="symmetric_cipher_init",
            quantum_safe=algo_rule.quantum_safe if algo_rule else False,
            nist_status=algo_rule.nist_status if algo_rule else "unknown",
            security_findings=sec_findings,
            raw_metadata={"c_macro": func_name}
        )

    def _process_digest_macro(self, file_path: Path, line_idx: int, col: int, func_name: str) -> SourceFinding:
        clean = func_name.replace("EVP_", "").lower()
        algo_id = "ALGO-SHA2-256"

        if "md5" in clean:
            algo_id = "ALGO-MD5"
        elif "sha1" in clean:
            algo_id = "ALGO-SHA1"
        elif "sha3_256" in clean:
            algo_id = "ALGO-SHA3-256"
        elif "sha3_512" in clean:
            algo_id = "ALGO-SHA3-512"
        elif "sha384" in clean:
            algo_id = "ALGO-SHA2-384"
        elif "sha512" in clean:
            algo_id = "ALGO-SHA2-512"
        elif "sha224" in clean:
            algo_id = "ALGO-SHA2-224"

        algo_rule = self.rule_engine.algorithms.get(algo_id)
        sec_findings = []
        if algo_id in ["ALGO-MD5", "ALGO-SHA1"]:
            sec_findings.append({
                "issue": f"Broken/insecure digest algorithm used: {algo_rule.name if algo_rule else algo_id}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="cpp",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive="hash",
            algorithm=algo_rule.name if algo_rule else "Digest",
            operation="digest_computation",
            quantum_safe=algo_rule.quantum_safe if algo_rule else False,
            nist_status=algo_rule.nist_status if algo_rule else "unknown",
            security_findings=sec_findings,
            raw_metadata={"c_macro": func_name}
        )

    def _process_fetch_call(self, file_path: Path, line_idx: int, col: int, fetch_func: str, algo_str: str) -> SourceFinding:
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(algo_str)

        mode = None
        for m in ["ecb", "cbc", "gcm", "ctr"]:
            if m in algo_str.lower():
                mode = m.upper()
                break

        sec_findings = []
        if mode == "ECB":
            sec_findings.append({
                "issue": f"Insecure block cipher mode 'ECB' fetched: {algo_str}",
                "severity": "CRITICAL"
            })

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="cpp",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=algo_rule.primitive if algo_rule else "cryptographic_operation",
            algorithm=algo_rule.name if algo_rule else algo_str.upper(),
            mode=mode,
            operation="algorithm_fetch",
            quantum_safe=algo_rule.quantum_safe if algo_rule else False,
            nist_status=algo_rule.nist_status if algo_rule else "unknown",
            security_findings=sec_findings,
            raw_metadata={"fetch_func": fetch_func, "algo_str": algo_str}
        )

    def _process_sodium_call(self, file_path: Path, line_idx: int, col: int, call_name: str) -> SourceFinding:
        mapping = {
            "crypto_box_keypair": ("X25519", "X25519", "key_exchange", False),
            "crypto_kx_keypair": ("X25519", "X25519", "key_exchange", False),
            "crypto_sign_keypair": ("Ed25519", "Ed25519", "signature", False),
            "crypto_secretbox_easy": ("XSalsa20-Poly1305", None, "symmetric_cipher", True),
            "crypto_auth": ("HMAC", None, "mac", True)
        }
        algo_name, curve, prim, q_safe = mapping.get(call_name, ("SodiumCrypto", None, "cryptographic_operation", False))
        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="cpp",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=algo_name,
            curve=curve,
            operation="keypair_generation" if "keypair" in call_name else "cryptographic_operation",
            quantum_safe=q_safe,
            nist_status="approved",
            security_findings=[],
            raw_metadata={"sodium_call": call_name}
        )

    def _process_oqs_call(self, file_path: Path, line_idx: int, col: int, func_name: str, algo_param: str) -> SourceFinding:
        clean = algo_param.replace("-", "").upper()
        if "KYBER" in clean or "MLKEM" in clean:
            canonical = "ML-KEM"
            prim = "key_encapsulation"
        elif "DILITHIUM" in clean or "MLDSA" in clean:
            canonical = "ML-DSA"
            prim = "signature"
        elif "SPHINCS" in clean or "SLHDSA" in clean:
            canonical = "SLH-DSA"
            prim = "signature"
        elif "FALCON" in clean:
            canonical = "Falcon"
            prim = "signature"
        elif "BIKE" in clean:
            canonical = "BIKE"
            prim = "key_encapsulation"
        elif "HQC" in clean:
            canonical = "HQC"
            prim = "key_encapsulation"
        else:
            canonical = algo_param
            prim = "key_encapsulation" if "KEM" in func_name else "signature"

        snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="cpp",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=prim,
            algorithm=canonical,
            operation="pqc_instantiation",
            quantum_safe=True,
            nist_status="fips_pqc_standard",
            security_findings=[],
            raw_metadata={"liboqs_call": func_name, "raw_algo": algo_param}
        )

    def _resolve_curve_nid(self, raw_nid: str) -> str:
        mapping = {
            "NID_X9_62_prime256v1": "NIST-P256",
            "NID_secp256r1": "NIST-P256",
            "NID_secp384r1": "NIST-P384",
            "NID_secp521r1": "NIST-P521",
            "NID_secp256k1": "secp256k1",
            "NID_X25519": "X25519",
            "NID_ED25519": "Ed25519",
            "NID_secp192r1": "secp192r1"
        }
        return mapping.get(raw_nid, raw_nid)

    def _map_op_to_algo(self, op: str) -> str:
        if "HMAC" in op:
            return "HMAC"
        elif "Digest" in op:
            return "MessageDigest"
        return "Cipher"

    def _map_op_to_operation(self, op: str) -> str:
        mapping = {
            "EVP_EncryptInit_ex": "encryption_init",
            "EVP_DecryptInit_ex": "decryption_init",
            "EVP_DigestSignInit": "digital_signature_init",
            "EVP_DigestVerifyInit": "signature_verification_init",
            "HMAC_Init_ex": "mac_computation_init"
        }
        return mapping.get(op, "cryptographic_operation")

    def _offset_to_line(self, content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1