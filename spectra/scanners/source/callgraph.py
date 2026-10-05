"""
spectra.scanners.source.callgraph
====================================
Precise, multi-level call-graph blast radius computation engine.
Performs AST and brace-depth enclosing function extraction (identifying user function abcd),
verifies import references across files, traces direct callers (level 1 efgh) via ripgrep,
and recursively maps indirect/transitive callers (level 2+ ijkl) to determine exact tree depth.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple

from spectra.utils.shell import command_exists, run_command


class CallGraphEngine:
    """Computes exact call-graph hierarchy metrics (direct callers, indirect callers, call depth)."""

    def __init__(
        self,
        project_root: Optional[Path] = None,
        excluded_dirs: Optional[List[str]] = None,
    ):
        self.project_root = project_root
        self.excluded_dirs = set(
            excluded_dirs or [
                ".git", "node_modules", "vendor", "target", "dist",
                "build", ".venv", "venv", "__pycache__", ".gradle", ".m2"
            ]
        )
        self._file_funcs_cache: Dict[str, List[Tuple[int, int, str, Optional[str]]]] = {}
        self._file_text_cache: Dict[str, str] = {}
        self._caller_cache: Dict[Tuple[str, str], Set[Tuple[Path, str]]] = {}
        self._tree_cache: Dict[Tuple[str, str], Tuple[int, int, int]] = {}

    def get_file_text(self, p: Path) -> str:
        """Retrieves and caches decoded text content for a source file."""
        s = str(p)
        if s not in self._file_text_cache:
            try:
                self._file_text_cache[s] = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                self._file_text_cache[s] = ""
        return self._file_text_cache[s]

    def find_enclosing_function(
        self,
        file_path: Path,
        line_number: int
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Locates the user function and optional class enclosing the given line number.
        Returns: (function_name, class_name)
        """
        if line_number <= 0:
            return None, None
        s = str(file_path.resolve()) if not str(file_path).startswith("/proc/") else str(file_path)
        if s not in self._file_funcs_cache:
            self._parse_file_funcs(file_path)

        funcs = self._file_funcs_cache.get(s, [])
        best_func = None
        best_class = None
        min_span = float("inf")

        for start, end, fn, cls in funcs:
            if start <= line_number <= end:
                span = end - start
                if span < min_span:
                    min_span = span
                    best_func = fn
                    best_class = cls

        return best_func, best_class

    def _parse_file_funcs(self, file_path: Path) -> None:
        """Parses function boundaries and enclosing classes for a source file."""
        s = str(file_path.resolve()) if not str(file_path).startswith("/proc/") else str(file_path)
        ext = file_path.suffix.lower()
        content = self.get_file_text(file_path)
        if not content:
            self._file_funcs_cache[s] = []
            return

        funcs: List[Tuple[int, int, str, Optional[str]]] = []

        if ext == ".py":
            try:
                tree = ast.parse(content, filename=s)

                class ClassTracker(ast.NodeVisitor):
                    def __init__(self):
                        self.class_stack: List[str] = []

                    def visit_ClassDef(self, node: ast.ClassDef):
                        self.class_stack.append(node.name)
                        self.generic_visit(node)
                        self.class_stack.pop()

                    def visit_FunctionDef(self, node: ast.FunctionDef):
                        start = node.lineno
                        end = getattr(node, "end_lineno", None) or (start + 50)
                        cls = self.class_stack[-1] if self.class_stack else None
                        funcs.append((start, end, node.name, cls))
                        self.generic_visit(node)

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                        start = node.lineno
                        end = getattr(node, "end_lineno", None) or (start + 50)
                        cls = self.class_stack[-1] if self.class_stack else None
                        funcs.append((start, end, node.name, cls))
                        self.generic_visit(node)

                ClassTracker().visit(tree)
            except Exception:
                pass
        else:
            # Brace-based parsing for Java, Kotlin, JS/TS, Go, Rust, C/C++
            patterns = [
                # Kotlin
                re.compile(r"^\s*(?:(?:private|public|internal|protected|override|suspend|inline)\s+)*fun\s+(?:<[^>]+>\s+)?(?:[a-zA-Z0-9_]+\.)?([a-zA-Z0-9_]+)\s*\("),
                # Go
                re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)\s*\("),
                # Rust
                re.compile(r"^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)\s*(?:<[^>]+>)?\s*\("),
                # Java & C++
                re.compile(r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default|native|inline|virtual|explicit)\s+)*(?:<[^>]+>\s+)?(?:[a-zA-Z0-9_<>\[\],\s:*&]+\s+)?([a-zA-Z0-9_]+)\s*\([^;]*?\)\s*(?:throws\s+[^{]+)?\s*\{"),
                # JS / TS
                re.compile(r"^\s*(?:(?:export|default|async|public|private|protected|static|readonly)\s+)*(?:function\s+([a-zA-Z0-9_]+)|(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|([a-zA-Z0-9_]+)\s*\([^;]*?\)\s*(?::\s*[^;{]+)?\s*\{)"),
            ]
            class_pattern = re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*(?:class|interface|struct)\s+([a-zA-Z0-9_]+)")
            lines = content.splitlines()
            current_cls = None
            brace_depth = 0
            pending_funcs: List[Tuple[int, int, str, Optional[str]]] = []

            for idx, line in enumerate(lines, 1):
                clean = line.strip()
                if clean.startswith(("//", "#", "*", "/*")):
                    continue

                cm = class_pattern.match(line)
                if cm:
                    current_cls = cm.group(1)

                for pat in patterns:
                    m = pat.match(line)
                    if m:
                        name = next((g for g in m.groups() if g), None)
                        if name and name not in (
                            "if", "for", "while", "switch", "catch", "synchronized",
                            "class", "interface", "struct", "enum"
                        ):
                            pending_funcs.append((brace_depth + 1, idx, name, current_cls))
                            break

                brace_depth += line.count("{") - line.count("}")
                for i in range(len(pending_funcs) - 1, -1, -1):
                    p_depth, p_start, p_name, p_cls = pending_funcs[i]
                    if brace_depth < p_depth:
                        funcs.append((p_start, idx, p_name, p_cls))
                        pending_funcs.pop(i)

            for p_depth, p_start, p_name, p_cls in pending_funcs:
                funcs.append((p_start, len(lines), p_name, p_cls))

        self._file_funcs_cache[s] = funcs

    def has_import_reference(self, caller: Path, target: Path, symbol: str) -> bool:
        """
        Verifies that caller file imports or references the target file or symbol.
        Prevents false-positive call graph matches between unrelated modules.
        """
        if caller.resolve() == target.resolve():
            return True

        ext = caller.suffix.lower()
        # In JVM, Go, and C/C++, files within the same directory share package/directory scope
        if ext in (".java", ".kt", ".go", ".c", ".cpp", ".cc", ".h", ".hpp"):
            if caller.parent.resolve() == target.parent.resolve():
                return True

        content = self.get_file_text(caller)
        target_stem = target.stem
        if len(target_stem) >= 3 and target_stem in content:
            return True
        if symbol and len(symbol) >= 3 and symbol in content:
            return True

        return False

    def find_callers(self, target_file: Path, func_name: str) -> Set[Tuple[Path, str]]:
        """
        Runs an optimized, targeted ripgrep search to find user functions calling func_name.
        Restricts searches to matching file extensions and respects exclusions and .gitignore.
        """
        if not func_name or len(func_name) < 2:
            return set()

        cache_key = (str(target_file.resolve()), func_name)
        if cache_key in self._caller_cache:
            return self._caller_cache[cache_key]

        if not command_exists("rg"):
            return set()

        ext = target_file.suffix.lower()
        ext_map = {
            ".py": ["*.py"],
            ".java": ["*.java", "*.kt"],
            ".kt": ["*.java", "*.kt"],
            ".ts": ["*.ts", "*.tsx", "*.js", "*.jsx"],
            ".tsx": ["*.ts", "*.tsx", "*.js", "*.jsx"],
            ".js": ["*.ts", "*.tsx", "*.js", "*.jsx"],
            ".jsx": ["*.ts", "*.tsx", "*.js", "*.jsx"],
            ".go": ["*.go"],
            ".rs": ["*.rs"],
            ".cpp": ["*.cpp", "*.cc", "*.c", "*.hpp", "*.h"],
            ".cc": ["*.cpp", "*.cc", "*.c", "*.hpp", "*.h"],
            ".c": ["*.cpp", "*.cc", "*.c", "*.hpp", "*.h"],
            ".h": ["*.cpp", "*.cc", "*.c", "*.hpp", "*.h"],
            ".hpp": ["*.cpp", "*.cc", "*.c", "*.hpp", "*.h"],
        }
        if not ext or ext not in ext_map:
            return set()

        search_root = self.project_root or target_file.parent
        search_root_str = str(search_root).replace("\\", "/")
        if search_root_str in ("/", "") or search_root_str.startswith("/proc"):
            return set()

        globs = ext_map[ext]

        cmd = ["rg", "-w", "-n", "--no-heading", "--color", "never"]
        for ex in self.excluded_dirs:
            cmd.extend(["-g", f"!**/{ex}/**"])
        for g in globs:
            cmd.extend(["-g", g])
        cmd.extend([func_name, str(search_root)])

        callers: Set[Tuple[Path, str]] = set()
        code, stdout, _ = run_command(cmd)

        if code in (0, 1) and stdout:
            for line in stdout.splitlines():
                if len(line) >= 2 and line[1] == ":" and (line[2] == "\\" or line[2] == "/"):
                    drive = line[:2]
                    rest = line[2:]
                    parts = rest.split(":", 2)
                    matched_file = Path(drive + parts[0])
                    matched_line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
                    line_code = parts[2] if len(parts) > 2 else ""
                else:
                    parts = line.split(":", 2)
                    matched_file = Path(parts[0])
                    matched_line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
                    line_code = parts[2] if len(parts) > 2 else ""

                clean = line_code.strip()
                # Skip comments and docstrings
                if clean.startswith(("//", "#", "*", "/*", "'''", '"""')):
                    continue

                # Skip function and class definition lines
                if clean.startswith(("def ", "fun ", "func ", "fn ", "function ", "public ", "private ", "class ")):
                    if f"{func_name}(" in clean or f"{func_name} (" in clean or f"class {func_name}" in clean:
                        continue

                # Skip python if __name__ == '__main__' check line itself
                if "if __name__" in clean:
                    continue

                # Check import reference
                if not self.has_import_reference(matched_file, target_file, func_name):
                    continue

                # Resolve enclosing user function in calling file
                caller_fn, caller_cls = self.find_enclosing_function(matched_file, matched_line)
                resolved_caller = caller_fn or "<module>"

                # Discard recursive self-call on same line/function
                if matched_file.resolve() == target_file.resolve() and resolved_caller == func_name:
                    continue

                callers.add((matched_file.resolve(), resolved_caller))

        self._caller_cache[cache_key] = callers
        return callers

    def compute_blast_radius(
        self,
        file_path: Path,
        symbol_name: str,
        line_number: int = 0
    ) -> Tuple[int, int, int]:
        """
        Computes the complete call-graph hierarchy:
        - Root: Enclosing user function (abcd)
        - Direct Calls: Functions calling abcd (level 1 efgh)
        - Indirect Calls: Functions calling efgh and subsequent levels (level 2+ ijkl)
        - Call Depth: Height of the call-tree hierarchy
        """
        root_fn, root_cls = self.find_enclosing_function(file_path, line_number)
        root_name = root_fn
        if not root_name or root_name == "__init__":
            root_name = root_cls or symbol_name or file_path.stem

        cache_key = (str(file_path.resolve()), root_name)
        if cache_key in self._tree_cache:
            return self._tree_cache[cache_key]

        visited: Set[Tuple[str, str]] = {(str(file_path.resolve()), root_name)}
        level_1 = self.find_callers(file_path, root_name)
        direct_callers: Set[Tuple[Path, str]] = set()

        for f, fn in level_1:
            k = (str(f.resolve()), fn)
            if k not in visited:
                visited.add(k)
                direct_callers.add((f, fn))

        if not direct_callers:
            res = (0, 0, 0)
            self._tree_cache[cache_key] = res
            return res

        direct_count = len(direct_callers)
        current_queue = direct_callers
        indirect_callers: Set[Tuple[Path, str]] = set()
        depth = 1

        while current_queue and depth < 10:
            next_queue: Set[Tuple[Path, str]] = set()
            for f, fn in current_queue:
                callers = self.find_callers(f, fn)
                for cf, cfn in callers:
                    k = (str(cf.resolve()), cfn)
                    if k not in visited:
                        visited.add(k)
                        next_queue.add((cf, cfn))
                        indirect_callers.add((cf, cfn))

            if not next_queue:
                break
            depth += 1
            current_queue = next_queue
            if len(indirect_callers) > 500:
                break

        res = (direct_count, len(indirect_callers), depth)
        self._tree_cache[cache_key] = res
        return res


_SHARED_ENGINE: Optional[CallGraphEngine] = None


def get_shared_callgraph_engine(
    project_root: Optional[Path] = None,
    excluded_dirs: Optional[List[str]] = None,
) -> CallGraphEngine:
    """Returns or initializes the singleton CallGraphEngine."""
    global _SHARED_ENGINE
    if _SHARED_ENGINE is None:
        _SHARED_ENGINE = CallGraphEngine(project_root=project_root, excluded_dirs=excluded_dirs)
    else:
        if project_root and _SHARED_ENGINE.project_root != project_root:
            _SHARED_ENGINE.project_root = project_root
        if excluded_dirs:
            _SHARED_ENGINE.excluded_dirs.update(excluded_dirs)
    return _SHARED_ENGINE
