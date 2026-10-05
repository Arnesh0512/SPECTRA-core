"""
spectra.scanners.source.python_scanner
===========================================
Python AST-based cryptographic scanner.
Inspects Python syntax trees to detect cryptographic operations, cipher modes,
key sizes, and insecure configurations without executing target code.
"""

import ast
from pathlib import Path
from typing import Dict, List, Optional, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


class CryptoASTVisitor(ast.NodeVisitor):
    """Walks the Python AST to locate and extract cryptographic operations."""

    def __init__(self, file_path: Path, rule_engine: RuleEngine, scanner_ref: BaseSourceScanner):
        self.file_path = file_path
        self.rule_engine = rule_engine
        self.scanner_ref = scanner_ref
        self.findings: List[SourceFinding] = []
        # Maps local aliases to fully qualified imports, e.g. {"AES": "Crypto.Cipher.AES"}
        self.imported_names: Dict[str, str] = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imported_names[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            full_name = f"{mod}.{alias.name}" if mod else alias.name
            asname = alias.asname or alias.name
            self.imported_names[asname] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._resolve_call_name(node.func)
        if call_name:
            self._analyze_call(call_name, node)
        self.generic_visit(node)

    def _resolve_call_name(self, func_node: ast.AST) -> str:
        """Resolves an AST node representing a function call into a string representation."""
        if isinstance(func_node, ast.Name):
            return self.imported_names.get(func_node.id, func_node.id)
        elif isinstance(func_node, ast.Attribute):
            val = self._resolve_call_name(func_node.value)
            return f"{val}.{func_node.attr}" if val else func_node.attr
        return ""

    def _analyze_call(self, call_name: str, node: ast.Call):
        """Matches resolved function calls against known cryptographic signatures."""
        python_rules = self.rule_engine.get_library_rules_for_language("python")

        # 1. Exact full-name match first (highest precedence)
        for lib in python_rules:
            for pattern in lib.call_patterns:
                if not pattern.call:
                    continue
                if call_name == pattern.call:
                    self._record_call_finding(pattern, node, call_name)
                    return

        # 2. Strict suffix match (e.g. "AES.new" matches "...Crypto.Cipher.AES.new")
        for lib in python_rules:
            for pattern in lib.call_patterns:
                if not pattern.call:
                    continue
                # Require a dot boundary to prevent 'rsa.generate' matching 'ec.generate'
                if call_name.endswith(f".{pattern.call}"):
                    self._record_call_finding(pattern, node, call_name)
                    return

        # 3. Specific prefix or import-guided match
        for lib in python_rules:
            for pattern in lib.call_patterns:
                if not pattern.call:
                    continue
                # If pattern is e.g. "hmac.new" and call is "hmac.new"
                # Avoid single-word collisions like "new", "generate", "sign"
                if "." in pattern.call and pattern.call.split(".")[-1] in call_name:
                    module_prefix = pattern.call.split(".")[0].lower()
                    if module_prefix in call_name.lower():
                        self._record_call_finding(pattern, node, call_name)
                        return

    def _record_call_finding(self, pattern: Any, node: ast.Call, full_call_name: str):
        algo_id = pattern.algo_id or pattern.default_algo_id
        algo_rule = self.rule_engine.algorithms.get(algo_id) if algo_id else None

        # Clean fallback derivation if rule not loaded directly
        if algo_rule:
            algo_name = algo_rule.name
            primitive = pattern.primitive or algo_rule.primitive
            quantum_safe = algo_rule.quantum_safe
            nist_status = algo_rule.nist_status
        else:
            if algo_id:
                algo_name = algo_id.replace("ALGO-", "")
            elif pattern.operation:
                algo_name = pattern.operation.upper()
            else:
                algo_name = full_call_name.split(".")[-1]

            primitive = pattern.primitive or "cryptographic_operation"
            quantum_safe = False
            nist_status = "unknown"

        mode_val = self._extract_cipher_mode(node)
        key_size = self._extract_key_size(node)
        curve_val = self._extract_curve(node, pattern)
        digest_arg = self._extract_digest_arg(node)

        # Build security issues list
        sec_findings = []
        if pattern.flag_insecure:
            issue_msg = getattr(pattern, "issue", None) or f"Deprecated or insecure cryptographic algorithm used ({algo_name})"
            sec_findings.append({
                "issue": issue_msg,
                "severity": "HIGH"
            })

        if mode_val and any(insec_m.lower() in mode_val.lower() for insec_m in pattern.flag_insecure_modes):
            sec_findings.append({
                "issue": f"Insecure cipher mode detected ({mode_val}) - vulnerable to pattern leakage",
                "severity": "CRITICAL"
            })

        if key_size and "key_size_less_than" in pattern.flag_insecure_if:
            threshold = pattern.flag_insecure_if["key_size_less_than"]
            if key_size < threshold:
                sec_findings.append({
                    "issue": f"Key size ({key_size} bits) is below the minimum secure threshold ({threshold} bits)",
                    "severity": "HIGH"
                })

        # Flag insecure curves
        if curve_val and any(insec_c.lower() in curve_val.lower() for insec_c in pattern.flag_insecure_curves):
            sec_findings.append({
                "issue": f"Insecure or deprecated elliptic curve used ({curve_val})",
                "severity": "HIGH"
            })

        # Flag insecure digest algorithms (e.g. hmac with MD5 or SHA1)
        if digest_arg and any(insec_d.lower() in digest_arg.lower() for insec_d in pattern.flag_insecure_if_digest):
            sec_findings.append({
                "issue": f"HMAC instantiated with broken digest algorithm ({digest_arg})",
                "severity": "HIGH"
            })

        # Flag insecure SSL protocols (e.g. PROTOCOL_TLSv1, PROTOCOL_SSLv3)
        ssl_arg = self._extract_ssl_protocol(node)
        if ssl_arg and any(p.lower() in ssl_arg.lower() for p in getattr(pattern, "flag_insecure_protocols", [])):
            sec_findings.append({
                "issue": f"Insecure/deprecated TLS protocol configured ({ssl_arg})",
                "severity": "CRITICAL"
            })

        code_snippet = self.scanner_ref.extract_snippet(self.file_path, node.lineno)

        # Compute call-graph and LOC metrics using BaseSourceScanner ripgrep helper
        symbol_name = full_call_name.split(".")[-1]
        dirs, trans, depth = self.scanner_ref.compute_call_metrics(self.file_path, symbol_name, line_number=node.lineno)

        finding = SourceFinding(
            language="python",
            file_path=str(self.file_path.resolve()),
            line_number=node.lineno,
            column_number=node.col_offset,
            code_snippet=code_snippet,
            primitive=primitive,
            algorithm=algo_name,
            key_size=key_size,
            mode=mode_val,
            curve=curve_val,
            operation=pattern.operation,
            quantum_safe=quantum_safe,
            nist_status=nist_status,
            direct_calls=dirs,
            transitive_calls=trans,
            call_depth=depth,
            security_findings=sec_findings,
            raw_metadata={
                "call_name": full_call_name,
                "operation": pattern.operation,
                "digestmod": digest_arg
            }
        )
        self.findings.append(finding)

    def _extract_cipher_mode(self, node: ast.Call) -> Optional[str]:
        """Extracts mode constants like modes.CBC(...) or AES.MODE_ECB."""
        for kw in node.keywords:
            if kw.arg in ("mode", "cipher_mode"):
                return self._resolve_mode_repr(kw.value)

        valid_modes = {"ECB", "CBC", "CTR", "GCM", "CFB", "OFB", "MODE_ECB", "MODE_CBC", "MODE_CTR", "MODE_GCM"}
        for arg in node.args:
            mode_str = self._resolve_mode_repr(arg)
            if mode_str and any(vm in mode_str.upper() for vm in valid_modes):
                return mode_str

        return None

    def _resolve_mode_repr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _extract_key_size(self, node: ast.Call) -> Optional[int]:
        """Extracts integer key size arguments (e.g., key_size=2048 or RSA.generate(1024))."""
        # Avoid treating random.randint(1, 100) or token_bytes(32) as key sizes unless related to keys
        func_name = self._resolve_call_name(node.func).lower()
        if any(ign in func_name for ign in ["random", "randint", "token_bytes", "token_hex"]):
            return None

        # Positional first argument if integer
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
            return node.args[0].value

        # Keyword arguments
        for kw in node.keywords:
            if kw.arg in ("key_size", "bits", "size", "nbits") and isinstance(kw.value, ast.Constant):
                val = getattr(kw.value, "value", None)
                if isinstance(val, int):
                    return val
        return None

    def _extract_curve(self, node: ast.Call, pattern: Any) -> Optional[str]:
        """Extracts curve arguments (e.g. ec.SECP256R1(), curve=curves.NIST256p)."""
        raw_curve = None

        for kw in node.keywords:
            if kw.arg in ("curve", "curve_name"):
                raw_curve = self._resolve_curve_repr(kw.value)
                break

        if not raw_curve and getattr(pattern, "curve_mappings", None):
            for arg in node.args:
                candidate = self._resolve_curve_repr(arg)
                if candidate:
                    for pattern_curve in pattern.curve_mappings.keys():
                        if pattern_curve.lower() in candidate.lower():
                            raw_curve = candidate
                            break
                if raw_curve:
                    break

        if not raw_curve:
            return None

        # Resolve to standard canonical name
        mappings = getattr(pattern, "curve_mappings", {})
        for pattern_curve, canonical_curve in mappings.items():
            if pattern_curve.lower() in raw_curve.lower():
                return canonical_curve

        return raw_curve

    def _resolve_curve_repr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call):
            return self._resolve_call_name(node.func)
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Name):
            return self.imported_names.get(node.id, node.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _extract_digest_arg(self, node: ast.Call) -> Optional[str]:
        """Extracts digest parameter for HMAC or hash instantiations."""
        target_node = None

        for kw in node.keywords:
            if kw.arg in ("digestmod", "digest", "hash_algorithm"):
                target_node = kw.value
                break

        if target_node is None and len(node.args) >= 3:
            target_node = node.args[2]

        if target_node is None:
            return None

        if isinstance(target_node, ast.Constant) and isinstance(target_node.value, str):
            return target_node.value
        elif isinstance(target_node, ast.Attribute):
            val = self._resolve_call_name(target_node.value)
            return f"{val}.{target_node.attr}" if val else target_node.attr
        elif isinstance(target_node, ast.Name):
            return self.imported_names.get(target_node.id, target_node.id)

        return self._resolve_call_name(target_node)

    def _extract_ssl_protocol(self, node: ast.Call) -> Optional[str]:
        """Extracts SSL/TLS protocol specification argument."""
        if node.args:
            return self._resolve_call_name(node.args[0])
        for kw in node.keywords:
            if kw.arg in ("protocol", "ssl_version"):
                return self._resolve_call_name(kw.value)
        return None


class PythonASTScanner(BaseSourceScanner):
    """Concrete scanner for Python source files (.py)."""

    def supported_extensions(self) -> List[str]:
        return [".py"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()

            tree = ast.parse(source_code, filename=str(file_path))
            visitor = CryptoASTVisitor(file_path, self.rule_engine, self)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            return []
        except Exception:
            return []