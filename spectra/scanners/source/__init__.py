"""
spectra.scanners.source
============================
Unified source code scanner coordinating dynamic rule-driven pre-filtering (ripgrep),
language-specific AST parsers, and project manifest dependency scanning.
"""

from pathlib import Path
import re
from typing import Dict, List, Set, Optional, Any, Callable

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step, log_warning
from spectra.utils.shell import command_exists, run_command

from .base import BaseSourceScanner, SourceFinding
from .python_scanner import PythonASTScanner
from .jvm_scanner import JVMScanner
from .js_ts_scanner import JSTSSParser
from .cpp_scanner import CPPScanner
from .go_scanner import GoScanner
from .rust_scanner import RustScanner
from .dependency_scanner import DependencyScanner
from .rules import DEFAULT_RULE_ENGINE, RuleEngine


class SourceScanOrchestrator:
    """Manages discovery and AST/manifest dispatch across all supported source code files."""

    def __init__(self, config: ScanConfig, rule_engine: RuleEngine = DEFAULT_RULE_ENGINE):
        self.config = config
        self.rule_engine = rule_engine
        self.scanners: List[BaseSourceScanner] = [
            PythonASTScanner(rule_engine=self.rule_engine),
            JVMScanner(rule_engine=self.rule_engine),
            JSTSSParser(rule_engine=self.rule_engine),
            CPPScanner(rule_engine=self.rule_engine),
            GoScanner(rule_engine=self.rule_engine),
            RustScanner(rule_engine=self.rule_engine),
        ]
        self.ext_to_scanner: Dict[str, BaseSourceScanner] = {}
        self.ecosystem_to_scanner: Dict[str, BaseSourceScanner] = {}
        
        for scanner in self.scanners:
            for ext in scanner.supported_extensions():
                self.ext_to_scanner[ext] = scanner
            
            lang_name = scanner.__class__.__name__.lower()
            if "python" in lang_name:
                self.ecosystem_to_scanner["python"] = scanner
            elif "js" in lang_name:
                self.ecosystem_to_scanner["javascript"] = scanner
                self.ecosystem_to_scanner["typescript"] = scanner
            elif "go" in lang_name:
                self.ecosystem_to_scanner["go"] = scanner
            elif "jvm" in lang_name:
                self.ecosystem_to_scanner["java"] = scanner
                self.ecosystem_to_scanner["kotlin"] = scanner
            elif "rust" in lang_name:
                self.ecosystem_to_scanner["rust"] = scanner
            elif "cpp" in lang_name:
                self.ecosystem_to_scanner["cpp"] = scanner

        self.dependency_scanner = DependencyScanner()

        # Build dynamic regex pattern for pre-filtering
        self.dynamic_crypto_regex = self._build_dynamic_regex()

    def scan(self, target_dir: Path, progress_callback: Optional[Any] = None) -> List[SourceFinding]:
        """Executes the complete multi-tier scan pipeline on the target directory."""
        log_step(f"Scanning source code in: {target_dir}")
        all_findings: List[SourceFinding] = []
        excluded = self.config.source_scanner.excluded_directories

        # 1. Dependency Analysis & Deep Disk/Function Scanning (Phase 2)
        dep_findings = self.dependency_scanner.scan_directory(
            target_dir, 
            excluded_dirs=excluded, 
            scanners_map=self.ecosystem_to_scanner,
            progress_callback=progress_callback
        )
        dep_decls = [f for f in dep_findings if f.raw_metadata.get("finding_type") == "crypto_capable_dependency"]
        dep_funcs = [f for f in dep_findings if f.raw_metadata.get("finding_type") == "dependency_function_analysis"]
        unique_pkgs = len(set(f.raw_metadata.get("package", "") for f in dep_decls))

        if dep_funcs:
            log_info(f"Discovered {len(dep_decls)} crypto dependency declaration(s) across manifests ({unique_pkgs} unique packages) and {len(dep_funcs)} internal function mapping(s).")
        else:
            log_info(f"Discovered {len(dep_decls)} crypto dependency declaration(s) across manifests ({unique_pkgs} unique packages).")
        all_findings.extend(dep_findings)

        # 2. Tier 1: Discover candidate files with crypto signatures
        candidate_files = self._find_candidates(target_dir)
        log_info(f"Identified {len(candidate_files)} candidate crypto source file(s) for deep analysis.")

        # 3. Tier 2: Deep AST / syntax analysis
        total_candidates = len(candidate_files)
        for idx, file_path in enumerate(candidate_files, start=1):
            main_lang = self.detect_module_main_language(file_path, target_dir)
            ext = file_path.suffix.lower()
            scanner = self.ext_to_scanner.get(ext)
            if scanner:
                findings = scanner.parse_file(file_path)
                for f in findings:
                    f.language = main_lang
                    if hasattr(f, "raw_metadata") and isinstance(f.raw_metadata, dict):
                        f.raw_metadata["module_language"] = main_lang
                        f.raw_metadata["language"] = main_lang
                all_findings.extend(findings)
            if progress_callback and total_candidates > 0:
                pct = 12.0 + (idx / total_candidates) * 28.0
                desc = f"Domain 1/4: AST Parsing ({idx}/{total_candidates}) [{main_lang}] {file_path.name}"
                progress_callback(desc, pct)

        log_info(f"Source scan completed with {len(all_findings)} finding(s).")
        return all_findings

    _LANG_CACHE: Dict[Path, str] = {}

    @classmethod
    def detect_module_main_language(cls, file_path: Path, root_dir: Optional[Path] = None) -> str:
        """
        Determines the primary module language for a file by inspecting parent module
        manifests and service directory names, mapping native/glue files (like C files in a Java service)
        back to their parent module's main language.
        """
        dir_key = file_path.parent
        if dir_key in cls._LANG_CACHE:
            return cls._LANG_CACHE[dir_key]

        manifest_langs = [
            (('build.gradle.kts',), 'kotlin'),
            (('pom.xml', 'build.gradle'), 'java'),
            (('tsconfig.json',), 'typescript'),
            (('package.json',), 'javascript'),
            (('pyproject.toml', 'requirements.txt', 'poetry.lock', 'pipfile', 'setup.py'), 'python'),
            (('go.mod', 'go.sum'), 'go'),
            (('cargo.toml', 'cargo.lock'), 'rust'),
        ]

        ext_langs = {
            '.py': 'python', '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin',
            '.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript', '.jsx': 'javascript',
            '.go': 'go', '.rs': 'rust', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
            '.hpp': 'cpp', '.c': 'c', '.h': 'c'
        }

        curr = file_path.parent
        root = root_dir if (root_dir and "/proc/" in str(root_dir)) else (root_dir.resolve() if root_dir else None)

        while curr:
            name_lower = curr.name.lower()

            try:
                entries = {p.name.lower() for p in curr.iterdir() if p.is_file()}
            except Exception:
                entries = set()

            for manifests, lang in manifest_langs:
                if any(m in entries for m in manifests):
                    res = lang
                    if lang == 'javascript' and ('tsconfig.json' in entries or any(p.suffix.lower() == '.ts' for p in curr.glob('*.ts'))):
                        res = 'typescript'
                    cls._LANG_CACHE[dir_key] = res
                    return res

            # CMake / C/C++ build manifests
            if any(m in entries for m in ('cmakelists.txt', 'vcpkg.json', 'conanfile.txt', 'meson.build')):
                res = 'cpp'
                if any(part in name_lower for part in ('-c', '_c')) or name_lower.endswith('c'):
                    res = 'c'
                cls._LANG_CACHE[dir_key] = res
                return res

            # Service/Module directory naming conventions
            for pattern, lang in [
                (r'[-_]?(java|jvm)[-_]?', 'java'),
                (r'[-_]?kotlin[-_]?', 'kotlin'),
                (r'[-_]?(py|python)[-_]?', 'python'),
                (r'[-_]?(go|golang)[-_]?', 'go'),
                (r'[-_]?(rs|rust)[-_]?', 'rust'),
                (r'[-_]?(ts|typescript)[-_]?', 'typescript'),
                (r'[-_]?(js|javascript)[-_]?', 'javascript'),
                (r'[-_]?(cpp|cplusplus)[-_]?', 'cpp'),
                (r'[-_]c[-_]?', 'c'),
            ]:
                if re.search(pattern, name_lower) or name_lower.endswith(f"-{lang}"):
                    cls._LANG_CACHE[dir_key] = lang
                    return lang

            if root and curr == root:
                break
            if curr.parent == curr:
                break
            curr = curr.parent

        fallback = ext_langs.get(file_path.suffix.lower(), 'source')
        cls._LANG_CACHE[dir_key] = fallback
        return fallback

    def _find_candidates(self, target_dir: Path) -> Set[Path]:
        """Finds candidate files via ripgrep if enabled/available, else uses Python fallback."""
        if self.config.source_scanner.use_ripgrep and command_exists("rg"):
            return self._run_ripgrep_filter(target_dir)
        return self._run_python_fallback_filter(target_dir)

    def _build_dynamic_regex(self) -> str:
        """
        Dynamically derives regex search tokens from all registered YAML rules
        and component catalogs.
        """
        raw_tokens: Set[str] = set()

        # 1. Pull imports and headers from loaded YAML libraries
        for lang, lib_rules in self.rule_engine.libraries_by_language.items():
            for lib in lib_rules:
                for imp in lib.imports:
                    raw_tokens.add(imp.split(".")[0])
                    raw_tokens.add(imp.replace(".", r"[/\\.]"))
                for hdr in lib.headers:
                    raw_tokens.add(hdr.replace("/", r"[/\\.]"))

                for cp in lib.call_patterns:
                    if cp.class_name:
                        raw_tokens.add(cp.class_name)
                    if cp.call and "." in cp.call:
                        raw_tokens.add(cp.call.split(".")[0])

        # 2. Ingest catalog anchors from dependencies rules
        for pkg in self.dependency_scanner.catalog:
            raw_tokens.add(pkg["name"])
            for alias in pkg.get("aliases", []):
                raw_tokens.add(alias)

        sorted_tokens = sorted(
            [re.escape(t).replace(r"\[/\\\.\]", r"[/\\.]") for t in raw_tokens if len(t) >= 3],
            key=len,
            reverse=True
        )
        return r"\b(" + "|".join(sorted_tokens) + r")"

    def _run_ripgrep_filter(self, target_dir: Path) -> Set[Path]:
        """Executes optimized ripgrep subprocess with exclusion and multiline matching."""
        candidates: Set[Path] = set()
        ext_globs = [g for ext in self.ext_to_scanner.keys() for g in ("-g", f"*{ext}")]
        exclude_globs = [g for ex in self.config.source_scanner.excluded_directories for g in ("-g", f"!**/{ex}/**")]

        cmd = [
            "rg", "-l", "-L", "--no-messages", "--color", "never", "--mmap", "--max-filesize", "5M",
            "-e", self.dynamic_crypto_regex, *ext_globs, *exclude_globs, str(target_dir)
        ]

        exit_code, stdout, stderr = run_command(cmd)
        if exit_code in (0, 1):
            for line in stdout.splitlines():
                if line.strip():
                    p = Path(line.strip())
                    if not str(p).startswith("/proc/"):
                        try:
                            p = p.resolve()
                        except Exception:
                            pass
                    candidates.add(p)
            return candidates

        log_warning(f"ripgrep returned code {exit_code} ({stderr.strip()}), falling back to Python file walker.")
        return self._run_python_fallback_filter(target_dir)

    def _run_python_fallback_filter(self, target_dir: Path) -> Set[Path]:
        """High-throughput pure-Python fallback candidate search."""
        candidates: Set[Path] = set()
        compiled_regex = re.compile(self.dynamic_crypto_regex, re.IGNORECASE)
        excluded_dirs = set(self.config.source_scanner.excluded_directories)
        max_lines = self.config.source_scanner.max_header_lines_checked

        for path in target_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.ext_to_scanner:
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    header_content = "".join([f.readline() for _ in range(max_lines)])
                    if compiled_regex.search(header_content):
                        candidates.add(path.resolve())
            except Exception:
                continue

        return candidates