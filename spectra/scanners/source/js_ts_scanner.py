"""
spectra.scanners.source.js_ts_scanner
==========================================
JavaScript and TypeScript source code cryptographic scanner.
Inspects Node.js 'crypto' module invocations, browser WebCrypto subtle APIs,
CryptoJS, node-forge, @noble/curves, TweetNaCl, and CodeQL ECDAT Layer 3 targets.
"""

from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# Node.js Cipher: createCipheriv('aes-256-gcm', key, iv) or createCipher('aes128', pass)
NODE_CIPHER_REGEX = re.compile(
    r'\b(?:crypto\.)?create(?P<action>Cipher|Decipher)(?:iv)?\s*\(\s*["\'](?P<algo>[^"\']+)["\']',
    re.IGNORECASE
)

# Node.js Hash / HMAC: createHash('sha256') or createHmac('sha256', key)
NODE_HASH_REGEX = re.compile(
    r'\b(?:crypto\.)?create(?P<type>Hash|Hmac)\s*\(\s*["\'](?P<algo>[^"\']+)["\']',
    re.IGNORECASE
)

# Node.js Digital Signature Factory: createSign('SHA256') or createVerify('RSA-SHA256')
NODE_SIGN_REGEX = re.compile(
    r'\b(?:crypto\.)?create(?P<type>Sign|Verify)\s*\(\s*["\'](?P<algo>[^"\']+)["\']',
    re.IGNORECASE
)

# Node.js KeyPair: generateKeyPairSync('rsa', { modulusLength: 1024, ... })
NODE_KEYPAIR_REGEX = re.compile(
    r'\b(?:crypto\.)?generateKeyPair(?:Sync)?\s*\(\s*["\'](?P<type>rsa|dsa|ec|ed25519|ed448|x25519|x448)["\'](?P<options>[^;]+)?',
    re.IGNORECASE
)

# CodeQL Ingested: Node.js Key Deserialization createPrivateKey / createPublicKey
NODE_KEY_LOAD_REGEX = re.compile(
    r'\b(?:crypto\.)?create(?P<kind>PrivateKey|PublicKey)\s*\(',
    re.IGNORECASE
)

# CodeQL Ingested: TLS & Secure Context Creation (tls.createSecureContext / https.createServer)
TLS_CONTEXT_REGEX = re.compile(
    r'\b(?:tls|https|crypto)\.(?P<method>createSecureContext|createServer)\s*\(\s*(?P<options>\{[^;]+?\})?',
    re.IGNORECASE
)

# CodeQL Ingested: Direct operational calls on receiver objects (signer.sign(), verifier.verify())
OP_EXEC_REGEX = re.compile(
    r'\b(?P<receiver>[a-zA-Z0-9_$]+)\s*\.\s*(?P<method>sign|verify)\s*\(',
    re.IGNORECASE
)

# Node.js ECDH: createECDH('secp256k1')
NODE_ECDH_REGEX = re.compile(
    r'\b(?:crypto\.)?createECDH\s*\(\s*["\'](?P<curve>[^"\']+)["\']',
    re.IGNORECASE
)

# WebCrypto Subtle: crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048 }, ...)
WEBCRYPTO_SUBTLE_REGEX = re.compile(
    r'\b(?:crypto|window\.crypto)\.subtle\.(?P<method>generateKey|encrypt|decrypt|sign|verify|digest|deriveKey|deriveBits)\s*\(\s*(?P<params>\{[^;]+?\}|["\'][^"\']+["\'])',
    re.IGNORECASE | re.DOTALL
)

# WebCrypto CSPRNG: crypto.getRandomValues(new Uint8Array(32)) or crypto.randomBytes(32)
CSPRNG_REGEX = re.compile(
    r'\b(?:crypto\.)?(?:getRandomValues|randomBytes|randomUUID)\s*\(',
    re.IGNORECASE
)

# Math.random() insecure PRNG in potential security context
MATH_RANDOM_REGEX = re.compile(
    r'\bMath\.random\s*\(\s*\)',
    re.IGNORECASE
)

# CryptoJS: CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.ECB })
CRYPTO_JS_REGEX = re.compile(
    r'\bCryptoJS\.(?P<algo>AES|DES|TripleDES|RC4|Rabbit|MD5|SHA1|SHA256|SHA512|HmacMD5|HmacSHA1|HmacSHA256)\.(?P<action>encrypt|decrypt)?(?P<args>\([^;]+?\))?',
    re.IGNORECASE
)

# Forge: forge.rsa.generateKeyPair({ bits: 1024 })
FORGE_REGEX = re.compile(
    r'\bforge\.(?:rsa\.generateKeyPair|cipher\.createCipher|md\.(?P<md>md5|sha1|sha256)\.create)(?P<args>\([^;]+?\))?',
    re.IGNORECASE
)

# Modern Noble / TweetNaCl: secp256k1.getPublicKey, nacl.sign.keyPair(), nacl.secretbox()
MODERN_ECC_REGEX = re.compile(
    r'\b(?P<lib>secp256k1|ed25519|x25519|nacl\.(?:sign|box|secretbox))\.(?P<method>getPublicKey|getSharedSecret|keyPair)?',
    re.IGNORECASE
)

# 15. JWT, JOSE, and Password Hashes (bcrypt, argon2, hkdf)
JWT_KDF_REGEX = re.compile(
    r'\b(?P<lib>jwt|bcrypt|argon2)\.(?P<method>sign|verify|hash|compare|PasswordHasher)|'
    r'\bnew\s+(?P<class>SignJWT)\b|\b(?P<bare_func>jwtVerify|hkdf)\s*\(',
    re.IGNORECASE
)


class JSTSSParser(BaseSourceScanner):
    """Scanner for JavaScript (.js, .jsx, .mjs, .cjs) and TypeScript (.ts, .tsx) files."""

    def supported_extensions(self) -> List[str]:
        return [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

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

        # 1. Node.js Cipher / Decipher
        for match in NODE_CIPHER_REGEX.finditer(content):
            algo_str = match.group("algo")
            action = match.group("action").lower()
            line_idx = self._offset_to_line(content, match.start())
            op = "symmetric_encryption_init" if action == "cipher" else "symmetric_decryption_init"
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=algo_str,
                default_primitive="symmetric_cipher",
                operation=op
            )
            if finding:
                _add_finding(finding, f"create{match.group('action')}")

        # 2. Node.js Hash / HMAC
        for match in NODE_HASH_REGEX.finditer(content):
            algo_str = match.group("algo")
            htype = match.group("type").lower()
            line_idx = self._offset_to_line(content, match.start())
            op = "digest_computation" if htype == "hash" else "mac_computation"
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=algo_str,
                default_primitive="hash" if htype == "hash" else "mac",
                operation=op
            )
            if finding:
                _add_finding(finding, f"create{match.group('type')}")

        # 3. Node.js Digital Signatures
        for match in NODE_SIGN_REGEX.finditer(content):
            algo_str = match.group("algo")
            stype = match.group("type").lower()
            line_idx = self._offset_to_line(content, match.start())
            op = "signature_generation" if stype == "sign" else "signature_verification"
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=algo_str,
                default_primitive="signature",
                operation=op
            )
            if finding:
                _add_finding(finding, f"create{match.group('type')}")

        # 4. Node.js KeyPair Generation (RSA, DSA, EC, ED25519)
        for match in NODE_KEYPAIR_REGEX.finditer(content):
            type_str = match.group("type")
            options_str = match.group("options") or ""
            line_idx = self._offset_to_line(content, match.start())

            key_size = self._extract_key_size_from_text(options_str)
            curve_name = self._extract_named_curve(options_str)

            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=type_str,
                default_primitive="public_key",
                operation="keypair_generation",
                key_size=key_size,
                curve=curve_name
            )
            if finding:
                _add_finding(finding, "generateKeyPair")

        # 5. CodeQL Target: Key Deserialization (createPrivateKey / createPublicKey)
        for match in NODE_KEY_LOAD_REGEX.finditer(content):
            kind = match.group("kind")
            line_idx = self._offset_to_line(content, match.start())
            snippet = self.extract_snippet(file_path, line_idx)
            finding = SourceFinding(
                source_domain="source_code",
                language="js_ts",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
                code_snippet=snippet,
                primitive="key_management",
                algorithm="AsymmetricKey",
                operation=f"load_{kind.lower()}",
                quantum_safe=False,
                nist_status="operational",
                security_findings=[],
                raw_metadata={"method": f"create{kind}"}
            )
            _add_finding(finding, f"create{kind}")

        # 6. CodeQL Target: TLS Contexts (createSecureContext / createServer)
        for match in TLS_CONTEXT_REGEX.finditer(content):
            method = match.group("method")
            opts = match.group("options") or ""
            line_idx = self._offset_to_line(content, match.start())

            sec_findings = []
            if any(p in opts.upper() for p in ["TLSV1", "TLSV1.0", "TLSV1.1", "SSLV3"]):
                sec_findings.append({
                    "issue": f"Insecure or deprecated TLS version specified in {method}()",
                    "severity": "CRITICAL"
                })

            snippet = self.extract_snippet(file_path, line_idx)
            finding = SourceFinding(
                source_domain="source_code",
                language="js_ts",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
                code_snippet=snippet,
                primitive="secure_transport",
                algorithm="TLS",
                operation="tls_session_init" if "Context" in method else "tls_server_init",
                quantum_safe=False,
                nist_status="approved",
                security_findings=sec_findings,
                raw_metadata={"method": method, "options": opts}
            )
            _add_finding(finding, method)

        # 7. CodeQL Target: Standalone Operational Calls (sign / verify)
        for match in OP_EXEC_REGEX.finditer(content):
            rec = match.group("receiver")
            method = match.group("method")
            if rec.lower() in ["math", "crypto"]:
                continue

            line_idx = self._offset_to_line(content, match.start())
            snippet = self.extract_snippet(file_path, line_idx)
            finding = SourceFinding(
                source_domain="source_code",
                language="js_ts",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
                code_snippet=snippet,
                primitive="signature",
                algorithm="DigitalSignature",
                operation="digital_signature" if method == "sign" else "signature_verification",
                quantum_safe=False,
                nist_status="operational",
                security_findings=[],
                raw_metadata={"receiver": rec, "method": method}
            )
            _add_finding(finding, method)

        # 8. Node.js ECDH
        for match in NODE_ECDH_REGEX.finditer(content):
            curve_str = match.group("curve")
            line_idx = self._offset_to_line(content, match.start())
            canonical_curve = self._resolve_curve_name(curve_str)
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token="ECDH",
                default_primitive="key_exchange",
                operation="key_agreement_init",
                curve=canonical_curve
            )
            if finding:
                _add_finding(finding, "createECDH")

        # 9. WebCrypto Subtle Calls
        for match in WEBCRYPTO_SUBTLE_REGEX.finditer(content):
            method = match.group("method")
            params = match.group("params")
            line_idx = self._offset_to_line(content, match.start())

            algo_name = self._extract_webcrypto_algo(params)
            curve_name = self._extract_named_curve(params)
            key_size = self._extract_key_size_from_text(params)

            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=algo_name,
                default_primitive=self._map_webcrypto_method_primitive(method),
                operation=f"webcrypto_{method}",
                key_size=key_size,
                curve=curve_name
            )
            if finding:
                _add_finding(finding, method)

        # 10. CryptoJS Invocations
        for match in CRYPTO_JS_REGEX.finditer(content):
            algo_str = match.group("algo")
            args_str = match.group("args") or ""
            line_idx = self._offset_to_line(content, match.start())

            mode = "ECB" if "mode.ECB" in args_str or "ECB" in args_str else None
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=algo_str,
                default_primitive="symmetric_cipher" if any(k in algo_str for k in ["AES", "DES", "RC4", "Rabbit"]) else "hash",
                operation="encryption" if "encrypt" in match.group(0) else "digest_computation",
                mode=mode
            )
            if finding:
                _add_finding(finding, algo_str)

        # 11. Node Forge
        for match in FORGE_REGEX.finditer(content):
            full_match = match.group(0)
            args_str = match.group("args") or ""
            line_idx = self._offset_to_line(content, match.start())

            if "rsa" in full_match:
                key_size = self._extract_key_size_from_text(args_str)
                finding = self._build_finding_from_token(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=match.start(),
                    token="RSA",
                    default_primitive="public_key",
                    operation="keypair_generation",
                    key_size=key_size
                )
                if finding:
                    _add_finding(finding, "generateKeyPair")
            else:
                md_name = match.group("md") or "sha256"
                finding = self._build_finding_from_token(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=match.start(),
                    token=md_name,
                    default_primitive="hash",
                    operation="digest_computation"
                )
                if finding:
                    _add_finding(finding, md_name)

        # 12. Modern Noble / TweetNaCl
        for match in MODERN_ECC_REGEX.finditer(content):
            lib_str = match.group("lib")
            line_idx = self._offset_to_line(content, match.start())

            token, curve, prim = self._resolve_noble_nacl(lib_str)
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token=token,
                default_primitive=prim,
                operation="keypair_generation",
                curve=curve
            )
            if finding:
                _add_finding(finding, lib_str.split(".")[0])

        # 13. CSPRNG (getRandomValues / randomBytes)
        for match in CSPRNG_REGEX.finditer(content):
            line_idx = self._offset_to_line(content, match.start())
            finding = self._build_finding_from_token(
                file_path=file_path,
                line_idx=line_idx,
                col=match.start(),
                token="CSPRNG",
                default_primitive="prng",
                operation="secure_random"
            )
            if finding:
                _add_finding(finding, "randomBytes")

        # 14. Math.random() in potential security context
        for match in MATH_RANDOM_REGEX.finditer(content):
            line_idx = self._offset_to_line(content, match.start())
            snippet = self.extract_snippet(file_path, line_idx)
            finding = SourceFinding(
                source_domain="source_code",
                language="js_ts",
                file_path=str(file_path.resolve()),
                line_number=line_idx,
                column_number=match.start(),
                code_snippet=snippet,
                primitive="prng",
                algorithm="Math.random",
                operation="insecure_random",
                quantum_safe=False,
                nist_status="broken_classical",
                security_findings=[{
                    "issue": "Non-cryptographic PRNG (Math.random) used in source code",
                    "severity": "HIGH"
                }],
                raw_metadata={"token": "Math.random"}
            )
            _add_finding(finding, "random")

        # 15. JWT, JOSE, Bcrypt, Argon2, HKDF
        for match in JWT_KDF_REGEX.finditer(content):
            lib = (match.group("lib") or match.group("class") or match.group("bare_func") or "").lower()
            method = match.group("method") or ""
            line_idx = self._offset_to_line(content, match.start())
            col = match.start()
            snippet = self.extract_snippet(file_path, line_idx)

            if "jwt" in lib or "signjwt" in lib or "jwtverify" in lib:
                algo = "JWT"
                prim = "signature"
                op = "token_generation" if ("sign" in method or "signjwt" in lib) else "token_verification"
                q_safe = False
            elif "bcrypt" in lib:
                algo = "bcrypt"
                prim = "key_derivation"
                op = "password_hash" if "hash" in method else "password_verify"
                q_safe = False
            elif "argon2" in lib:
                algo = "Argon2"
                prim = "key_derivation"
                op = "password_hash"
                q_safe = True
            elif "hkdf" in lib:
                algo = "HKDF"
                prim = "key_derivation"
                op = "key_derivation"
                q_safe = True
            else:
                algo = "GenericKDF"
                prim = "key_derivation"
                op = "key_derivation"
                q_safe = False

            finding = SourceFinding(
                source_domain="source_code",
                language="js_ts",
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
                raw_metadata={"js_call": match.group(0)}
            )
            _add_finding(finding, method or algo)

        return findings

    def _build_finding_from_token(
        self,
        file_path: Path,
        line_idx: int,
        col: int,
        token: str,
        default_primitive: str,
        operation: Optional[str] = None,
        key_size: Optional[int] = None,
        curve: Optional[str] = None,
        mode: Optional[str] = None
    ) -> Optional[SourceFinding]:
        cleaned_token = token.strip()
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(cleaned_token)

        algo_name = algo_rule.name if algo_rule else cleaned_token.upper()
        primitive = algo_rule.primitive if algo_rule else default_primitive
        quantum_safe = algo_rule.quantum_safe if algo_rule else False
        nist_status = algo_rule.nist_status if algo_rule else "unknown"

        # Check for modes inside the string e.g. "aes-256-ecb"
        if not mode:
            parts = cleaned_token.lower().replace("_", "-").split("-")
            for m in ["ecb", "cbc", "gcm", "ctr", "cfb", "ofb"]:
                if m in parts:
                    mode = m.upper()
                    break

        sec_findings = []
        if mode == "ECB":
            sec_findings.append({
                "issue": f"Insecure block cipher mode 'ECB' detected in token '{cleaned_token}'",
                "severity": "CRITICAL"
            })

        if any(weak in cleaned_token.upper() for weak in ["MD5", "SHA1", "DES", "3DES", "TRIPLEDES", "RC4"]):
            sec_findings.append({
                "issue": f"Broken or deprecated algorithm '{cleaned_token}' invoked in JavaScript/TypeScript",
                "severity": "HIGH"
            })

        if key_size and key_size < 2048 and any(k in algo_name.upper() for k in ["RSA", "DSA"]):
            sec_findings.append({
                "issue": f"Key size ({key_size} bits) is below the minimum recommended threshold (2048 bits)",
                "severity": "HIGH"
            })

        if curve and any(c in curve.lower() for c in ["192", "160"]):
            sec_findings.append({
                "issue": f"Insecure or deprecated elliptic curve specified: {curve}",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="js_ts",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=primitive,
            algorithm=algo_name,
            key_size=key_size,
            mode=mode,
            curve=curve,
            operation=operation,
            quantum_safe=quantum_safe,
            nist_status=nist_status,
            security_findings=sec_findings,
            raw_metadata={"raw_token": cleaned_token, "operation": operation}
        )

    def _extract_key_size_from_text(self, text: str) -> Optional[int]:
        m = re.search(r'\b(?:modulusLength|bits|length)\s*:\s*(?P<size>\d+)', text, re.IGNORECASE)
        if m:
            return int(m.group("size"))
        return None

    def _extract_named_curve(self, text: str) -> Optional[str]:
        m = re.search(r'\bnamedCurve\s*:\s*["\'](?P<curve>[^"\']+)["\']', text, re.IGNORECASE)
        if m:
            return self._resolve_curve_name(m.group("curve"))
        return None

    def _extract_webcrypto_algo(self, params_text: str) -> str:
        clean = params_text.strip().strip("'\"")
        if clean.isalnum() or "-" in clean:
            return clean

        m = re.search(r'\bname\s*:\s*["\'](?P<algo>[^"\']+)["\']', params_text, re.IGNORECASE)
        if m:
            return m.group("algo")
        return "WebCrypto"

    def _resolve_curve_name(self, raw: str) -> str:
        mapping = {
            "secp256r1": "NIST-P256",
            "prime256v1": "NIST-P256",
            "p-256": "NIST-P256",
            "p-384": "NIST-P384",
            "secp384r1": "NIST-P384",
            "p-521": "NIST-P521",
            "secp521r1": "NIST-P521",
            "secp256k1": "secp256k1",
            "x25519": "X25519",
            "ed25519": "Ed25519"
        }
        return mapping.get(raw.lower(), raw)

    def _map_webcrypto_method_primitive(self, method: str) -> str:
        mapping = {
            "generateKey": "key_generation",
            "encrypt": "symmetric_cipher",
            "decrypt": "symmetric_cipher",
            "sign": "signature",
            "verify": "signature",
            "digest": "hash",
            "deriveKey": "key_derivation",
            "deriveBits": "key_derivation"
        }
        return mapping.get(method, "cryptographic_operation")

    def _resolve_noble_nacl(self, lib_str: str) -> Tuple[str, str, str]:
        if "secp256k1" in lib_str:
            return "ECDSA", "secp256k1", "signature"
        elif "ed25519" in lib_str:
            return "Ed25519", "Ed25519", "signature"
        elif "x25519" in lib_str:
            return "X25519", "X25519", "key_exchange"
        elif "nacl.sign" in lib_str:
            return "Ed25519", "Ed25519", "signature"
        elif "nacl.box" in lib_str:
            return "X25519", "X25519", "key_exchange"
        elif "nacl.secretbox" in lib_str:
            return "XSalsa20-Poly1305", "", "symmetric_cipher"
        return "ECC", "", "public_key"

    def _offset_to_line(self, content: str, offset: int) -> int:
        return content.count("\n", 0, offset) + 1