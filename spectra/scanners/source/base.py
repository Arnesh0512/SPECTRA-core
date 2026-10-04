"""
spectra.scanners.source.base
=================================
Abstract base class and data schemas for source code cryptographic scanners.
Guarantees identical finding structures across all supported programming languages.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import subprocess
from spectra.utils.shell import command_exists, run_command
from .rules import RuleEngine, DEFAULT_RULE_ENGINE


@dataclass
class SourceFinding:
    """Standardized finding representation produced by any source code or dependency scanner."""
    source_domain: str = "source_code"
    language: str = ""
    file_path: str = ""
    line_number: int = 0
    column_number: int = 0
    code_snippet: str = ""
    primitive: str = "unknown"
    algorithm: str = "unknown"
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    operation: Optional[str] = None
    quantum_safe: bool = False
    nist_status: str = "unknown"
    # Call-graph metrics for dynamic Y calculation
    direct_calls: int = 0
    transitive_calls: int = 0
    call_depth: int = 0
    loc: int = 10
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding dataclass to a plain serializable dictionary."""
        return {
            "source_domain": self.source_domain,
            "language": self.language,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "primitive": self.primitive,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "mode": self.mode,
            "padding": self.padding,
            "curve": self.curve,
            "operation": self.operation,
            "quantum_safe": self.quantum_safe,
            "nist_status": self.nist_status,
            "direct_calls": self.direct_calls,
            "transitive_calls": self.transitive_calls,
            "call_depth": self.call_depth,
            "loc": self.loc,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


class BaseSourceScanner(ABC):
    """Abstract base class that all language parsers must implement."""

    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rule_engine = rule_engine or DEFAULT_RULE_ENGINE

    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Returns list of file extensions handled by this scanner."""
        pass

    @abstractmethod
    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        """Parses a single source file and returns discovered cryptographic operations."""
        pass

    def extract_snippet(self, file_path: Path, line_number: int, context: int = 1) -> str:
        """Reads surrounding lines of code to provide context for the finding."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            start = max(0, line_number - 1 - context)
            end = min(len(lines), line_number + context)
            return "".join(lines[start:end]).strip()
        except Exception:
            return ""

    def compute_call_metrics(self, file_path: Path, symbol_name: str) -> tuple[int, int, int]:
        """
        Uses fast, targeted ripgrep to trace direct callers and compute blast radius metrics.
        """
        if not symbol_name:
            return 0, 0, 0

        # Don't compute blast radius for external system/vendor libraries
        lower_parts = [p.lower() for p in file_path.parts]
        if any(p in lower_parts for p in ["node_modules", "site-packages", ".venv", "vendor", ".m2", "program files", "usr", "target", ".gradle", "build"]):
            return 0, 0, 0

        cache_key = (str(file_path), symbol_name)
        if not hasattr(self, "_metrics_cache"):
            self._metrics_cache = {}
        if cache_key in self._metrics_cache:
            return self._metrics_cache[cache_key]

        if not command_exists("rg"):
            return 0, 0, 0

        project_root = file_path.parent.parent
        direct_call_files: Set[str] = set()

        EXCLUDE_ARGS = [
            "-L",
            "-g", "!**/target/**",
            "-g", "!**/.gradle/**",
            "-g", "!**/node_modules/**",
            "-g", "!**/.venv/**",
            "-g", "!**/build/**",
            "-g", "!**/dist/**",
            "-g", "!**/.git/**",
            "-g", "!**/vendor/**",
            "-g", "!**/.m2/**",
        ]

        # Find direct callers referencing symbol_name or importing the module file stem
        file_stem = file_path.stem
        search_terms = [symbol_name]
        COMMON_STEMS = {"main", "init", "config", "app", "util", "utils", "test", "tests", "base", "types", "index", "common", "constants"}
        if len(file_stem) >= 4 and file_stem.lower() not in COMMON_STEMS:
            search_terms.append(file_stem)

        curr_file_str = str(file_path) if "/proc/" in str(file_path) else str(file_path.resolve())
        visited_files = {curr_file_str}

        for term in search_terms:
            if len(term) < 2:
                continue
            cmd = ["rg", "-w", "--no-heading", "--line-number", *EXCLUDE_ARGS, term, str(project_root)]
            code, stdout, _ = run_command(cmd)
            if code in (0, 1) and stdout:
                for line in stdout.splitlines():
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        p_str = parts[0]
                        matched_file = p_str if "/proc/" in p_str else str(Path(p_str).resolve())
                        if matched_file not in visited_files:
                            direct_call_files.add(matched_file)
                            visited_files.add(matched_file)

        direct_calls_count = len(direct_call_files)
        transitive_calls = int(direct_calls_count * 1.5)
        call_depth = min(3, direct_calls_count)

        res = (direct_calls_count, transitive_calls, call_depth)
        self._metrics_cache[cache_key] = res
        return res