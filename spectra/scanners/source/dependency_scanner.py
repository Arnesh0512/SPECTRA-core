"""
spectra.scanners.source.dependency_scanner
===============================================
Discovers declared and locked crypto-capable dependencies across:
Python, JVM (Maven/Gradle), JS/TS (npm/yarn/pnpm), Go (mod/sum),
Rust (Cargo), and C++ (CMake, vcpkg, Conan).
Separates rule definitions into rules/dependencies.yaml.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
import xml.etree.ElementTree as element_tree
import yaml

from .base import SourceFinding
from .dependency_analyzer import DependencyAnalyzer


MANIFEST_NAMES: Set[str] = {
    "requirements.txt", "constraints.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "package.json", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum", "cargo.toml", "cargo.lock", "cmakelists.txt",
    "conanfile.txt", "conanfile.py", "vcpkg.json", "vcpkg-configuration.json", "meson.build", "cpm.cmake",
}


def _line_for(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return 1


def _dep_item(name: str, version: Optional[str], relationship: str, line: Optional[int]) -> Dict[str, Any]:
    return {
        "name": name.strip(),
        "version": version.strip() if version else None,
        "relationship": relationship,
        "line": line or 1,
    }


class DependencyScanner:
    """Discovers declared and locked cryptographic dependencies across software projects."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "dependencies.yaml"
        self.rules_file = rules_file
        self.catalog = self._load_catalog(rules_file)
        self.analyzer = DependencyAnalyzer()

    def _load_catalog(self, path: Path) -> List[Dict[str, Any]]:
        if not path.is_file():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("packages", []) if isinstance(data, dict) else []
        except Exception:
            return []

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        scanners_map: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> List[SourceFinding]:
        """Walks target directory for manifest files, extracts crypto dependencies, and runs disk analysis."""
        import os
        import time

        findings: List[SourceFinding] = []
        excluded = set(excluded_dirs or [])

        # Phase 1: Rapidly locate all manifest files safely using os.walk
        manifest_files: List[Path] = []
        try:
            for root, dirs, files in os.walk(str(target_dir)):
                dirs[:] = [
                    d for d in dirs 
                    if d not in excluded and not any(part in excluded for part in Path(root, d).parts)
                ]
                for file_name in files:
                    name = file_name.lower()
                    if name in MANIFEST_NAMES or (name.startswith("requirements-") and name.endswith(".txt")):
                        manifest_files.append(Path(root) / file_name)
        except Exception:
            pass

        # Phase 2: Parse manifests and collect candidate crypto dependencies
        candidate_deps: List[Tuple[Path, str, Dict[str, Any]]] = []
        for file_path in manifest_files:
            configuration = self._parser_for(file_path)
            if not configuration:
                continue

            ecosystem, parser = configuration
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
                observations = list(parser(file_path, text))
            except Exception:
                continue

            for raw in observations:
                pkg_name = raw.get("name")
                if pkg_name and self._is_crypto_capable(pkg_name, ecosystem):
                    candidate_deps.append((file_path, ecosystem, raw))

        total_deps = len(candidate_deps)
        if total_deps == 0:
            if progress_callback:
                progress_callback("Domain 1/4: Analyzing Dependencies (0 crypto packages declared)", 12.0)
            return findings

        # Phase 3: Scan, analyze, and report each candidate dependency
        # Pacing ensures each module is visibly displayed in the Rich progress bar
        sleep_budget = min(0.04, max(0.01, 1.2 / total_deps))
        start_pct = 5.0
        end_pct = 12.0

        analyzed_cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        seen_findings: Set[Tuple[str, str, int]] = set()

        for idx, (file_path, ecosystem, raw) in enumerate(candidate_deps, start=1):
            t_start = time.time()
            pkg_name = str(raw["name"])
            pct = start_pct + (idx / total_deps) * (end_pct - start_pct)

            # High-visibility progress report showing exact language/ecosystem and module name
            # e.g.: Domain 1/4: Dependency (1/43) [python] cryptography
            desc = f"Domain 1/4: Dependency ({idx}/{total_deps}) [{ecosystem}] {pkg_name}"
            
            # Resolve the actual installation path of the package on disk
            installed_path = self.analyzer.locate_library_path(pkg_name, ecosystem, target_dir, manifest_file=file_path)
            from spectra.utils.system_paths import format_display_path
            if installed_path and installed_path.exists():
                rel_loc = format_display_path(installed_path, target_dir)
            else:
                manifest_rel = format_display_path(file_path, target_dir)
                rel_loc = f"[dim](not installed: {manifest_rel})[/dim]"

            if progress_callback:
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_deps}",
                        "type": "depedency",
                        "filename": pkg_name,
                        "location": rel_loc,
                    }
                )

            pkg_key = (ecosystem, pkg_name.lower())
            has_internal_analysis = False
            if scanners_map:
                if pkg_key not in analyzed_cache:
                    analyzed_cache[pkg_key] = self.analyzer.analyze_dependency(
                        pkg_name, ecosystem, target_dir, scanners_map, manifest_file=file_path
                    )
                analysis_results = analyzed_cache[pkg_key]
                if analysis_results:
                    has_internal_analysis = True
                    for res in analysis_results:
                        f_item = self._build_analysis_finding(res, target_dir, file_path, ecosystem=ecosystem)
                        key = (f_item.algorithm, f_item.file_path, f_item.line_number)
                        if key not in seen_findings:
                            seen_findings.add(key)
                            findings.append(f_item)

            # Only fallback to unanalyzed package-level finding if no internal functions were analyzed
            if not has_internal_analysis:
                finding = self._build_finding(raw, ecosystem, target_dir, file_path, installed_path=installed_path)
                key = (finding.algorithm, finding.file_path, finding.line_number)
                if key not in seen_findings:
                    seen_findings.add(key)
                    findings.append(finding)

            # Maintain animation fidelity so user can see each language and module

            import time
            from random import random
            time.sleep(random())



            elapsed = time.time() - t_start
            if elapsed < sleep_budget:
                time.sleep(sleep_budget - elapsed)

        return findings

    def _build_analysis_finding(self, res: Dict[str, Any], root: Path, file: Path, ecosystem: str = "dependency") -> SourceFinding:
        """Constructs an enriched finding with internal encryption and call graph metrics (Step 4)."""
        actual_file = res.get("file_path") or str(file)
        file_p = str(actual_file) if "/proc/" in str(actual_file) else str(Path(actual_file).resolve())
        line_num = int(res.get("line_number") or 1)
        return SourceFinding(
            source_domain="source_code",
            language=ecosystem,
            file_path=file_p,
            line_number=line_num,
            column_number=1,
            code_snippet=f"Module: {res['module_name']} | Function: {res['function_called']} | Internal Crypto: {res['encryption_internally']}",
            primitive="cryptographic_operation",
            algorithm=res["encryption_internally"],
            operation="library_dependency_call",
            quantum_safe=False,
            nist_status="approved",
            direct_calls=res["direct_calls"],
            transitive_calls=res["indirect_calls"],
            call_depth=res["call_depth"],
            loc=15,
            security_findings=[],
            raw_metadata={
                "finding_type": "dependency_function_analysis",
                "language": ecosystem,
                "ecosystem": ecosystem,
                "module_name": res["module_name"],
                "package": res["module_name"],
                "function_called": res["function_called"],
                "encryption_internally": res["encryption_internally"],
                "codebase_caller": res["codebase_caller"],
                "direct_calls": res["direct_calls"],
                "indirect_calls": res["indirect_calls"]
            }
        )

    def _build_finding(self, raw: Dict[str, Any], ecosystem: str, root: Path, file: Path, installed_path: Optional[Path] = None) -> SourceFinding:
        if installed_path and installed_path.exists():
            if installed_path.is_file():
                file_p = str(installed_path) if "/proc/" in str(installed_path) else str(installed_path.resolve())
            else:
                entry_candidates = ["index.js", "index.ts", "main.js", "__init__.py", "lib.rs", "main.go"]
                chosen = None
                for cand in entry_candidates:
                    if (installed_path / cand).is_file():
                        chosen = installed_path / cand
                        break
                target = chosen if chosen else installed_path
                file_p = str(target) if "/proc/" in str(target) else str(target.resolve())
            line_num = 1
        else:
            file_p = str(file) if "/proc/" in str(file) else str(file.resolve())
            line_num = int(raw.get("line") or 1)
        rel_path = str(file.relative_to(root).as_posix()) if file.is_relative_to(root) else file_p
        pkg_name = str(raw["name"])
        version = raw.get("version")

        metadata: Dict[str, Any] = {
            "finding_type": "crypto_capable_dependency",
            "language": ecosystem,
            "ecosystem": ecosystem,
            "package": pkg_name,
            "module_name": pkg_name,
            "dependency_relationship": raw.get("relationship", "direct"),
            "operation": "dependency_declaration",
        }
        if version:
            metadata["version"] = version

        return SourceFinding(
            source_domain="source_code",
            language=ecosystem,
            file_path=file_p,
            line_number=line_num,
            column_number=1,
            code_snippet=f"[{ecosystem}] {pkg_name} ({version or 'any'}) [{raw.get('relationship', 'direct')}]",
            primitive="key_management",
            algorithm=pkg_name,
            key_size=None,
            mode=None,
            padding=None,
            curve=None,
            operation="dependency_declaration",
            quantum_safe=False,
            nist_status="approved",
            security_findings=[],
            raw_metadata=metadata,
        )

    def _normalized(self, value: str) -> str:
        return value.lower().replace("_", "-").strip()

    def _is_crypto_capable(self, package: str, ecosystem: str) -> bool:
        pkg_norm = self._normalized(package)
        ecosystem_candidates = {ecosystem}
        if ecosystem in ["java", "kotlin", "java_or_kotlin"]:
            ecosystem_candidates.update({"java", "kotlin", "java_or_kotlin"})
        if ecosystem in ["javascript", "typescript", "javascript_or_typescript"]:
            ecosystem_candidates.update({"javascript", "typescript", "javascript_or_typescript"})

        for known in self.catalog:
            known_ecosystems = set(known.get("ecosystems", []))
            if not ecosystem_candidates.intersection(known_ecosystems):
                continue

            known_names = [known["name"], *known.get("aliases", [])]
            if pkg_norm in {self._normalized(n) for n in known_names}:
                return True
            if any(pkg_norm.startswith(self._normalized(prefix)) for prefix in known.get("prefixes", [])):
                return True
        return False

    def _parser_for(self, file: Path) -> Optional[Tuple[str, Callable[[Path, str], Iterable[Dict[str, Any]]]]]:
        name = file.name.lower()
        if name in {"requirements.txt", "constraints.txt"} or name.startswith("requirements-"):
            return "python", self._parse_requirements
        if name == "pyproject.toml":
            return "python", self._parse_pyproject
        if name == "poetry.lock":
            return "python", self._parse_poetry_lock
        if name == "pom.xml":
            return "java", self._parse_pom
        if name in {"build.gradle", "build.gradle.kts"}:
            ecosystem = "kotlin" if name.endswith(".kts") else "java"
            return ecosystem, self._parse_gradle
        if name == "gradle.lockfile":
            ecosystem = "kotlin" if (file.parent / "build.gradle.kts").exists() else "java"
            return ecosystem, lambda f, t: self._parse_gradle(f, t, "unknown")
        if name == "package.json":
            ecosystem = "typescript" if (file.parent / "tsconfig.json").exists() else "javascript"
            return ecosystem, self._parse_package_json
        if name == "package-lock.json":
            ecosystem = "typescript" if (file.parent / "tsconfig.json").exists() else "javascript"
            return ecosystem, self._parse_package_lock
        if name in {"yarn.lock", "pnpm-lock.yaml"}:
            ecosystem = "typescript" if (file.parent / "tsconfig.json").exists() else "javascript"
            return ecosystem, self._parse_yarn_or_pnpm
        if name == "go.mod":
            return "go", self._parse_go_mod
        if name == "go.sum":
            return "go", self._parse_go_sum
        if name == "cargo.toml":
            return "rust", self._parse_cargo_toml
        if name == "cargo.lock":
            return "rust", self._parse_cargo_lock
        if name in {"cmakelists.txt", "conanfile.txt", "conanfile.py", "meson.build", "cpm.cmake"}:
            return "cpp", self._parse_cpp_build
        if name in {"vcpkg.json", "vcpkg-configuration.json"}:
            return "cpp", self._parse_vcpkg
        return None

    # --- Parsers ---

    def _parse_requirements(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        for number, line in enumerate(text.splitlines(), start=1):
            clean = line.split("#", 1)[0].strip()
            if not clean or clean.startswith(("-", ".", "http:")):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(?:===|==|>=|<=|~=|!=|>|<)?\s*([^;\s]+)?", clean)
            if match:
                yield _dep_item(match.group(1), match.group(2), "direct", number)

    def _parse_poetry_lock(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        name = version = None
        start_line = None
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip() == "[[package]]":
                if name:
                    yield _dep_item(name, version, "unknown", start_line)
                name = version = None
                start_line = number
            elif match := re.match(r'\s*name\s*=\s*"([^"]+)"', line):
                name = match.group(1)
            elif match := re.match(r'\s*version\s*=\s*"([^"]+)"', line):
                version = match.group(1)
        if name:
            yield _dep_item(name, version, "unknown", start_line)

    def _parse_pyproject(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        section = ""
        for number, line in enumerate(text.splitlines(), start=1):
            if match := re.match(r"\s*\[([^]]+)\]", line):
                section = match.group(1).lower()
                continue
            if section in {"project", "tool.poetry.dependencies", "tool.poetry.group.dev.dependencies"}:
                if match := re.match(r'\s*([A-Za-z0-9_.-]+)\s*=\s*["\']?([^"\'#]+)', line):
                    name, value = match.groups()
                    if name not in {"python", "dependencies"}:
                        yield _dep_item(name, value.strip(), "direct", number)
            if section == "project" and "dependencies" in line:
                for dependency in re.findall(r'["\']([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*([^"\';,]*)', line):
                    yield _dep_item(dependency[0], dependency[1].strip() or None, "direct", number)

    def _parse_pom(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        try:
            root = element_tree.fromstring(text)
        except element_tree.ParseError:
            return
        namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
        dependencies = root.findall(".//m:dependencies/m:dependency", namespace) or root.findall(".//dependencies/dependency")
        for dependency in dependencies:
            group = dependency.findtext("m:groupId", namespaces=namespace) or dependency.findtext("groupId")
            artifact = dependency.findtext("m:artifactId", namespaces=namespace) or dependency.findtext("artifactId")
            version = dependency.findtext("m:version", namespaces=namespace) or dependency.findtext("version")
            if group and artifact:
                yield _dep_item(f"{group}:{artifact}", version, "direct", _line_for(text, f"<artifactId>{artifact}</artifactId>"))

    def _parse_gradle(self, file: Path, text: str, relationship: str = "direct") -> Iterable[Dict[str, Any]]:
        for number, line in enumerate(text.splitlines(), start=1):
            for match in re.finditer(r"['\"]([\w.-]+):([\w.-]+):([^'\"]+)['\"]", line):
                yield _dep_item(f"{match.group(1)}:{match.group(2)}", match.group(3), relationship, number)
            if relationship != "direct":
                match = re.match(r"\s*([\w.-]+):([\w.-]+):([^=]+)=", line)
                if match:
                    yield _dep_item(f"{match.group(1)}:{match.group(2)}", match.group(3), relationship, number)

    def _parse_package_json(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                yield _dep_item(name, str(version), "direct", _line_for(text, f'"{name}"'))

    def _parse_package_lock(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        root_package = data.get("packages", {}).get("", {})
        root_dependencies = set()
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            root_dependencies.update(root_package.get(section, {}))
        for name, details in data.get("dependencies", {}).items():
            if isinstance(details, dict):
                relationship = "direct" if name in root_dependencies else "unknown"
                yield _dep_item(name, details.get("version"), relationship, _line_for(text, f'"{name}"'))
        for package_path, details in data.get("packages", {}).items():
            if package_path and isinstance(details, dict):
                name = package_path.rsplit("node_modules/", 1)[-1]
                relationship = "direct" if name in root_dependencies else "transitive"
                yield _dep_item(name, details.get("version"), relationship, _line_for(text, f'"{package_path}"'))

    def _parse_yarn_or_pnpm(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        package_name = None
        for number, line in enumerate(text.splitlines(), start=1):
            if match := re.match(r'^((?:@[^/]+/)?[^@:\s]+)@[^:]+:', line):
                package_name = match.group(1)
                continue
            if match := re.match(r'^\s+version\s+["\']?([^"\']+)', line):
                if package_name:
                    yield _dep_item(package_name, match.group(1), "unknown", number)
            if match := re.match(r"^\s{2}/((?:@[^/]+/)?[^@/]+)@([^:]+):", line):
                yield _dep_item(match.group(1), match.group(2), "unknown", number)

    def _parse_go_mod(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        inside_require = False
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("require ("):
                inside_require = True
                continue
            if inside_require and stripped == ")":
                inside_require = False
                continue
            if stripped.startswith("require "):
                stripped = stripped.removeprefix("require ")
            elif not inside_require:
                continue
            parts = stripped.split()
            if len(parts) >= 2 and not stripped.startswith("//"):
                yield _dep_item(parts[0], parts[1], "transitive" if "// indirect" in stripped else "direct", number)

    def _parse_go_sum(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        for number, line in enumerate(text.splitlines(), start=1):
            parts = line.split()
            if len(parts) >= 2:
                yield _dep_item(parts[0], parts[1].removesuffix("/go.mod"), "unknown", number)

    def _parse_cargo_toml(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        section = ""
        for number, line in enumerate(text.splitlines(), start=1):
            if match := re.match(r"\s*\[([^]]+)\]", line):
                section = match.group(1)
                continue
            if "dependencies" in section:
                if match := re.match(r'\s*([\w-]+)\s*=\s*(?:["\']([^"\']+)["\']|\{[^}]*version\s*=\s*["\']([^"\']+))', line):
                    yield _dep_item(match.group(1), match.group(2) or match.group(3), "direct", number)

    def _parse_cargo_lock(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        name = version = None
        start_line = None
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip() == "[[package]]":
                if name:
                    yield _dep_item(name, version, "unknown", start_line)
                name = version = None
                start_line = number
            elif match := re.match(r'\s*name\s*=\s*"([^"]+)"', line):
                name = match.group(1)
            elif match := re.match(r'\s*version\s*=\s*"([^"]+)"', line):
                version = match.group(1)
        if name:
            yield _dep_item(name, version, "unknown", start_line)

    def _parse_cpp_build(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        for number, line in enumerate(text.splitlines(), start=1):
            if match := re.search(r"find_package\s*\(\s*([\w+.-]+)(?:\s+([^ )]+))?", line, re.IGNORECASE):
                yield _dep_item(match.group(1), match.group(2), "direct", number)
            if match := re.search(r"FetchContent_Declare\s*\(\s*([\w+.-]+)", line, re.IGNORECASE):
                yield _dep_item(match.group(1), None, "direct", number)
            if match := re.match(r"\s*([\w+.-]+)\s*/\s*([\w+.-]+)", line):
                yield _dep_item(match.group(1), match.group(2), "direct", number)

    def _parse_vcpkg(self, file: Path, text: str) -> Iterable[Dict[str, Any]]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for dependency in data.get("dependencies", []):
            name = dependency if isinstance(dependency, str) else dependency.get("name")
            if name:
                yield _dep_item(name, None, "direct", _line_for(text, name))