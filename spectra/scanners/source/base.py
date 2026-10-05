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

    def compute_call_metrics(
        self,
        file_path: Path,
        symbol_name: str,
        line_number: int = 0
    ) -> tuple[int, int, int]:
        """
        Uses CallGraphEngine to resolve enclosing user function (abcd),
        trace direct callers (efgh), and recursively map indirect callers (ijkl)
        to compute exact tree depth and blast radius metrics.
        """
        if not symbol_name and line_number <= 0:
            return 0, 0, 0

        # Don't compute blast radius for external system/vendor libraries
        lower_parts = [p.lower() for p in file_path.parts]
        if any(p in lower_parts for p in ["node_modules", "site-packages", ".venv", "vendor", ".m2", "program files", "usr", "target", ".gradle", "build"]):
            return 0, 0, 0

        if not hasattr(self, "callgraph_engine") or getattr(self, "callgraph_engine", None) is None:
            from .callgraph import get_shared_callgraph_engine
            self.callgraph_engine = get_shared_callgraph_engine()

        return self.callgraph_engine.compute_blast_radius(file_path, symbol_name, line_number=line_number)