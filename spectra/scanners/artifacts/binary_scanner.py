"""
spectra.scanners.artifacts.binary_scanner
==============================================
Executable binary and shared object cryptographic scanner.
Discovers linked cryptographic shared libraries, symbol table entries,
and binary string constants across ELF, PE, and Mach-O files.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set
import yaml

from spectra.utils.shell import command_exists, extract_printable_strings, run_command


@dataclass
class BinaryFinding:
    """Represents cryptographic evidence found within a binary file[cite: 28]."""
    source_domain: str = "artifacts"
    artifact_type: str = "compiled_binary"
    file_path: str = ""
    binary_format: str = "unknown"
    linked_crypto_libraries: List[str] = field(default_factory=list)
    detected_symbols: List[str] = field(default_factory=list)
    detected_algorithms: List[str] = field(default_factory=list)
    quantum_safe: bool = False
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "binary_format": self.binary_format,
            "linked_crypto_libraries": self.linked_crypto_libraries,
            "detected_symbols": self.detected_symbols,
            "detected_algorithms": self.detected_algorithms,
            "quantum_safe": self.quantum_safe,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


class BinaryScanner:
    """Discovers and inspects compiled binaries for cryptographic linkages using rules/binary_indicators.yaml[cite: 28]."""

    BINARY_EXTENSIONS = {".so", ".dll", ".dylib", ".exe", ".bin", ""}

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "binary_indicators.yaml"
        self.indicators = self._load_indicators(rules_file)
        self.crypto_shared_libs = set(self.indicators.get("libraries", {}).keys())
        
        sym_patterns = self.indicators.get("symbol_patterns", [])
        self.symbol_regex = re.compile(r"\b(" + "|".join(sym_patterns) + r")\w*\b", re.IGNORECASE) if sym_patterns else re.compile(r"$^")

        algo_patterns = self.indicators.get("algorithm_patterns", [])
        self.algo_regex = re.compile(r"\b(" + "|".join(algo_patterns) + r")\b", re.IGNORECASE) if algo_patterns else None

    def _load_indicators(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {"libraries": {}, "symbol_patterns": [], "algorithm_patterns": []}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {"libraries": {}, "symbol_patterns": [], "algorithm_patterns": []}

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[BinaryFinding]:
        findings: List[BinaryFinding] = []
        excluded = set(excluded_dirs or [])

        bin_files: List[Path] = []
        import os
        try:
            for root, dirs, files in os.walk(str(target_dir)):
                dirs[:] = [
                    d for d in dirs
                    if d not in excluded and not any(part in excluded for part in Path(root, d).parts)
                ]
                for file_name in files:
                    p = Path(root) / file_name
                    if p.suffix.lower() in self.BINARY_EXTENSIONS and self._is_binary_file(p):
                        bin_files.append(p)
        except Exception:
            pass

        total_bins = len(bin_files)
        for idx, path in enumerate(bin_files, start=1):
            if progress_callback and total_bins > 0:
                pct = 52.0 + (idx / total_bins) * 6.0
                desc = f"Domain 2/4: Auditing Binary ({idx}/{total_bins}) {path.name}"
                from spectra.utils.system_paths import format_display_path
                rel_loc = format_display_path(path, target_dir)
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_bins}",
                        "type": "binary",
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )
            finding = self.scan_binary(path, target_dir=target_dir)
            if finding:
                findings.append(finding)

        return findings

    def scan_binary(self, file_path: Path, target_dir: Optional[Path] = None) -> Optional[BinaryFinding]:
        binary_fmt = self._detect_format(file_path)
        if binary_fmt == "non_binary":
            return None

        linked_libs: Set[str] = set()
        detected_symbols: Set[str] = set()
        detected_algos: Set[str] = set()

        # 1. Inspect dynamic shared libraries[cite: 28]
        if binary_fmt == "ELF" and command_exists("readelf"):
            code, stdout, _ = run_command(["readelf", "-d", str(file_path)])
            if code == 0:
                for line in stdout.splitlines():
                    if "NEEDED" in line:
                        for clib in self.crypto_shared_libs:
                            if clib in line.lower():
                                linked_libs.add(self.indicators["libraries"][clib])

        # 2. Inspect symbol tables[cite: 28]
        if binary_fmt == "ELF" and command_exists("readelf"):
            code, stdout, _ = run_command(["readelf", "-s", "--wide", str(file_path)])
            if code == 0:
                for match in self.symbol_regex.finditer(stdout):
                    detected_symbols.add(match.group(0))

        # 3. String pool extraction fallback & explicit algorithm matching[cite: 28]
        strings = extract_printable_strings(file_path, min_length=4, limit=30000)
        for s in strings:
            for clib in self.crypto_shared_libs:
                if clib in s.lower():
                    linked_libs.add(self.indicators["libraries"][clib])
            for sm in self.symbol_regex.finditer(s):
                detected_symbols.add(sm.group(0))
            if self.algo_regex:
                for am in self.algo_regex.finditer(s):
                    detected_algos.add(am.group(0))

        if not (linked_libs or detected_symbols or detected_algos):
            return None

        sec_findings = []
        for sym in detected_symbols:
            if "md5" in sym.lower() or "des" in sym.lower() or "rc4" in sym.lower():
                sec_findings.append({
                    "issue": f"Legacy/broken cryptographic symbol referenced in binary: {sym}",
                    "severity": "HIGH"
                })
        for algo in detected_algos:
            if "ECB" in algo.upper():
                sec_findings.append({
                    "issue": f"Insecure ECB cipher mode reference detected in binary string pool: {algo}",
                    "severity": "HIGH"
                })

        # Enhanced check for Post-Quantum cryptographic linkage in compiled binaries
        pqc_identifiers = {"ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "SPHINCS", "LIBOQS"}
        is_quantum_safe = any(
            any(pqc in item.upper() for pqc in pqc_identifiers)
            for item in list(linked_libs) + list(detected_symbols) + list(detected_algos)
        )

        from spectra.utils.system_paths import format_display_path
        return BinaryFinding(
            source_domain="artifacts",
            artifact_type="compiled_binary",
            file_path=format_display_path(file_path, target_dir),
            binary_format=binary_fmt,
            linked_crypto_libraries=sorted(list(linked_libs)),
            detected_symbols=sorted(list(detected_symbols)),
            detected_algorithms=sorted(list(detected_algos)),
            quantum_safe=is_quantum_safe,
            security_findings=sec_findings,
            raw_metadata={"strings_analyzed_count": len(strings), "host_path": str(file_path)}
        )

    def _detect_format(self, file_path: Path) -> str:
        """Determines binary header type using magic byte inspection[cite: 28]."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
            if header.startswith(b"\x7fELF"):
                return "ELF"
            elif header.startswith(b"MZ"):
                return "PE"
            elif header in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                return "Mach-O"
            return "unknown"
        except Exception:
            return "non_binary"

    def _is_binary_file(self, file_path: Path) -> bool:
        """Checks if file contains null bytes within the first 1024 bytes[cite: 28]."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
            return b"\x00" in chunk
        except Exception:
            return False