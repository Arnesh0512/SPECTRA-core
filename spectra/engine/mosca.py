"""
spectra.engine.mosca
=========================
Quantum risk evaluation engine applying Michele Mosca's Theorem:
If (X + Y > Z), the system is vulnerable to quantum compromise before
post-quantum remediation can be completed. Loaded via cbom_policy.json.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json
import math
import fnmatch
import subprocess
import shutil
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from .normalizer import NormalizedCryptoAsset

console = Console()


@dataclass
class MoscaEvaluation:
    """Quantum exposure metrics and Mosca inequality calculation for an asset."""
    asset_id: str
    algorithm: str
    shelf_life_x: float
    migration_time_y: float
    quantum_threshold_z: int
    is_inequality_breached: bool
    risk_level: str
    sndl_vulnerable: bool
    recommended_pqc_replacement: str
    rationale: str
    scenario_name: str = "pessimistic"

    def to_dict(self) -> Dict:
        return {
            "asset_id": self.asset_id,
            "algorithm": self.algorithm,
            "shelf_life_x": self.shelf_life_x,
            "migration_time_y": self.migration_time_y,
            "quantum_threshold_z": self.quantum_threshold_z,
            "is_inequality_breached": self.is_inequality_breached,
            "risk_level": self.risk_level,
            "sndl_vulnerable": self.sndl_vulnerable,
            "recommended_pqc_replacement": self.recommended_pqc_replacement,
            "rationale": self.rationale,
            "scenario_name": self.scenario_name,
        }


def parse_gitignore(target_dir: Path) -> List[str]:
    """Parses .gitignore patterns if present safely."""
    patterns = []
    if not target_dir:
        return patterns
    gitignore_path = Path(target_dir) / ".gitignore"
    if gitignore_path.is_file():
        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except Exception:
            pass
    return patterns


def is_ignored(path: Path, target_dir: Path, gitignore_patterns: List[str], excluded_dirs: set) -> bool:
    """Checks if a file matches .gitignore or standard exclusion directories."""
    try:
        rel_path = path.relative_to(target_dir)
    except ValueError:
        return True

    for part in rel_path.parts:
        if part in excluded_dirs:
            return True

    rel_str = rel_path.as_posix()
    for pattern in gitignore_patterns:
        cleaned_pattern = pattern.rstrip("/")
        if fnmatch.fnmatch(rel_str, cleaned_pattern) or fnmatch.fnmatch(path.name, cleaned_pattern):
            return True
        if pattern.endswith("/") and any(fnmatch.fnmatch(p, cleaned_pattern) for p in rel_path.parts):
            return True

    return False


def count_codebase_loc(target_dir: Optional[Any], excluded_dirs: Optional[List[str]] = None) -> int:
    """
    Directly scans the target directory (ignoring .gitignore and library exclusions)
    to compute the true codebase-wide Lines of Code (LOC) safely.
    """
    if not target_dir:
        return 10000
    
    target_path = Path(target_dir)
    try:
        if not target_path.exists():
            return 10000
    except (PermissionError, OSError):
        return 10000

    excluded = set(excluded_dirs or [
        ".git", "node_modules", "vendor", "target", "dist", 
        "build", ".venv", "venv", "__pycache__", ".tox", ".pytest_cache"
    ])
    
    gitignore_patterns = parse_gitignore(target_path)
    source_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", 
        ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".tf", ".hcl", ".json", ".yaml", ".yml"
    }

    total_loc = 0
    try:
        for path in target_path.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in source_extensions:
                continue
            if is_ignored(path, target_path, gitignore_patterns, excluded):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    total_loc += sum(1 for _ in f)
            except Exception:
                pass
    except Exception:
        pass

    return max(1000, total_loc)


class MoscaRiskEngine:
    """Evaluates quantum risk exposure across cryptographic assets using Mosca's inequality and multi-scenario Z horizons."""

    # Class-level shared cache so resolved X persists across engine instances without re-prompting
    _shared_resolved_shelf_life_x: Optional[float] = None

    def __init__(self, policy_file: Optional[Path] = None, staff_size: int = 6):
        if policy_file is None:
            policy_file = Path(__file__).resolve().parent.parent.parent / "cbom_policy.json"
        self.policy = self._load_policy(policy_file)
        
        # Load all three CRQC arrival scenarios from policy[cite: 10]
        self.scenarios = self.policy.get("crqc_arrival_scenarios", {
            "pessimistic": 2033,
            "central": 2038,
            "optimistic": 2045
        })
        self.shelf_life_categories = self.policy.get("default_shelf_life_x", {})
        self.algorithm_risks = self.policy.get("algorithm_risk_definitions", {})
        self.staff_size = max(1, staff_size)

    def _load_policy(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def _scan_x_with_ripgrep(self, target_dir: Optional[Any]) -> Optional[float]:
        """
        Scans the codebase for value of X (shelf-life / data classification) using ripgrep (rg).
        """
        if not target_dir or not shutil.which("rg"):
            return None

        target_path = Path(target_dir)
        try:
            if not target_path.exists():
                return None
        except (PermissionError, OSError):
            return None

        search_terms = list(self.shelf_life_categories.keys()) + ["shelf_life", "data_classification", "classification"]
        pattern = "|".join(search_terms)

        try:
            result = subprocess.run(
                ["rg", "-i", "--count-matches", pattern, str(target_path)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                category_counts = {cat: 0 for cat in self.shelf_life_categories}
                for line in result.stdout.splitlines():
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        match_text = parts[0].lower()
                        for cat in category_counts:
                            if cat.replace("_", "") in match_text.replace("_", ""):
                                try:
                                    category_counts[cat] += int(parts[1])
                                except ValueError:
                                    pass

                best_cat = max(category_counts, key=category_counts.get) if category_counts else None
                if best_cat and category_counts[best_cat] > 0:
                    return float(self.shelf_life_categories[best_cat]["years"])
        except Exception:
            pass

        return None

    def _prompt_user_for_shelf_life(self) -> float:
        """
        Safely prompts user via native input() so keystrokes remain visible on screen.
        """
        if not sys.stdin.isatty():
            default_val = 7.0
            console.print(f"[bold yellow]ℹ Non-interactive environment detected. Defaulting shelf-life X to {default_val} years.[/bold yellow]")
            return default_val

        console.print("\n[bold yellow]ℹ Data classification / shelf-life (X) could not be automatically detected via ripgrep scan.[/bold yellow]")
        console.print("[bold cyan]Please select the appropriate data shelf-life category for this codebase:[/bold cyan]\n")

        cat_keys = [k for k in self.shelf_life_categories.keys() if k != "custom_user_defined"]
        for idx, key in enumerate(cat_keys, start=1):
            info = self.shelf_life_categories[key]
            years = info.get("years")
            desc = info.get("description")
            console.print(f"  [bold white]{idx}.[/bold white] [cyan]{key}[/cyan] ([bold green]{years} yrs[/bold green]) - {desc}")

        none_of_above_idx = len(cat_keys) + 1
        console.print(f"  [bold white]{none_of_above_idx}.[/bold white] [bold bright_yellow]None of the above[/bold bright_yellow] - Specify custom data retention / shelf-life (X) in years")

        console.print()
        while True:
            try:
                # Use standard input() so typed characters appear visibly on screen
                choice = input("Enter the numerical number of the category [5]: ").strip()
                if not choice:
                    choice = "5"
                num = int(choice)
                if 1 <= num <= len(cat_keys):
                    selected_key = cat_keys[num - 1]
                    val = float(self.shelf_life_categories[selected_key]["years"])
                    console.print(f"[green]✔ Selected category '{selected_key}' ({val} years)[/green]\n")
                    return val
                elif num == none_of_above_idx:
                    while True:
                        custom_input = input("↳ Enter custom data shelf-life (X) in years (e.g., 2.5, 12, 50) [7.0]: ").strip()
                        if not custom_input:
                            custom_val = 7.0
                            break
                        try:
                            custom_val = float(custom_input)
                            if custom_val > 0:
                                break
                            console.print("[bold red]Please enter a positive number of years.[/bold red]")
                        except ValueError:
                            console.print("[bold red]Invalid number. Please enter a valid float or integer (e.g., 5.5).[/bold red]")

                    console.print(f"[green]✔ Configured custom shelf-life (X = {custom_val} years)[/green]\n")

                    self.shelf_life_categories["custom_user_defined"] = {
                        "years": custom_val,
                        "description": "User-specified custom data retention / shelf-life period"
                    }

                    # Persist custom value to cbom_policy.json
                    try:
                        p_file = getattr(self, "policy_file", None) or (Path(__file__).resolve().parent.parent.parent / "cbom_policy.json")
                        if p_file.exists():
                            with open(p_file, "r", encoding="utf-8") as f_policy:
                                p_data = json.load(f_policy)
                            if "default_shelf_life_x" not in p_data:
                                p_data["default_shelf_life_x"] = {}
                            p_data["default_shelf_life_x"]["custom_user_defined"] = {
                                "years": custom_val,
                                "description": "User-specified custom data retention / shelf-life period"
                            }
                            with open(p_file, "w", encoding="utf-8") as f_policy:
                                json.dump(p_data, f_policy, indent=2)
                    except Exception:
                        pass

                    return custom_val
            except (ValueError, EOFError, KeyboardInterrupt):
                console.print("\n[bold yellow]Input stream interrupted or invalid. Defaulting to 7.0 years.[/bold yellow]")
                return 7.0
            console.print("[bold red]Invalid selection. Please enter a valid number from the menu.[/bold red]")

    def get_resolved_shelf_life_x(self, target_dir: Optional[Any] = None) -> float:
        """Resolves X via ripgrep scan first; falls back safely if not found."""
        if MoscaRiskEngine._shared_resolved_shelf_life_x is not None:
            return MoscaRiskEngine._shared_resolved_shelf_life_x

        scanned_val = self._scan_x_with_ripgrep(target_dir)
        if scanned_val is not None:
            MoscaRiskEngine._shared_resolved_shelf_life_x = scanned_val
            return scanned_val

        prompted_val = self._prompt_user_for_shelf_life()
        MoscaRiskEngine._shared_resolved_shelf_life_x = prompted_val
        return prompted_val

    def _calculate_cocomo_baseline_y(self, total_repository_loc: int) -> float:
        kloc = max(1.0, total_repository_loc / 1000.0)
        effort_person_months = 3.0 * (kloc ** 1.12)
        migration_years = effort_person_months / (self.staff_size * 12.0)
        return round(migration_years, 2)

    def _calculate_dynamic_y(self, asset: NormalizedCryptoAsset, total_repository_loc: int) -> float:
        cocomo_baseline = self._calculate_cocomo_baseline_y(total_repository_loc)

        w1 = 1.0
        w2 = 1.2
        w3 = 0.4
        dir_calls = getattr(asset, "direct_calls", 0)
        trans_calls = getattr(asset, "transitive_calls", 0)
        depth = max(1, getattr(asset, "call_depth", 1))

        local_multiplier = (w1 + (w2 * dir_calls) + (w3 * trans_calls * depth))
        if getattr(asset, "is_upstream_dependency", False):
            local_multiplier *= 2.5

        # 2. Domain-specific adjustments (Infrastructure, Certificates, Network)
        domain_modifier = 1.0
        if getattr(asset, "source_domain", "") == "infrastructure":
            domain_modifier = 1.5
        elif getattr(asset, "source_domain", "") == "network":
            domain_modifier = 1.4

        blended_y = cocomo_baseline * 0.4 + (local_multiplier * domain_modifier * 0.6)
        return max(0.5, round(blended_y, 2))

    def evaluate_asset_for_scenario(self, asset: NormalizedCryptoAsset, scenario_name: str, target_year: int, total_repository_loc: int = 10000, target_dir: Optional[Any] = None) -> MoscaEvaluation:
        current_year = datetime.now().year
        z = max(1, target_year - current_year)
        
        # Kept as float to preserve precision for fractional shelf lives (e.g. 0.01)
        x = float(self.get_resolved_shelf_life_x(target_dir))
        y = self._calculate_dynamic_y(asset, total_repository_loc)

        algo_val = getattr(asset, "algorithm", "UNKNOWN")
        if isinstance(algo_val, list):
            algo_upper = " ".join(str(a) for a in algo_val).upper()
            algo_str = ", ".join(str(a) for a in algo_val)
        else:
            algo_upper = str(algo_val).upper()
            algo_str = str(algo_val)

        if getattr(asset, "quantum_safe", False) or not getattr(asset, "shor_vulnerable", True):
            return MoscaEvaluation(
                asset_id=f"{getattr(asset, 'asset_id', 'unknown')}-{scenario_name}", algorithm=algo_str,
                shelf_life_x=x, migration_time_y=0.0, quantum_threshold_z=z,
                is_inequality_breached=False, risk_level="QUANTUM_SAFE",
                sndl_vulnerable=False, recommended_pqc_replacement="None (Quantum Safe)",
                rationale=f"[{scenario_name.capitalize()} Scenario] Asset is inherently quantum-resistant.",
                scenario_name=scenario_name
            )

        # Classical asymmetric primitives are vulnerable to Shor's algorithm
        breached = (x + y) > z
        risk_def = self.algorithm_risks.get(algo_upper, {})
        base_severity = risk_def.get("severity", "HIGH")
        replacement = risk_def.get("replacement", "ML-KEM-768 / ML-DSA-65")

        # ENHANCEMENT 2: Guarded Mosca SNDL logic for Post-Quantum KEMs
        is_pqc_kem = any(pqc in algo_upper for pqc in ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA"])
        sndl = (not is_pqc_kem) and any(ind in algo_upper for ind in ["ECDH", "DH", "RSA", "ECC", "X25519"])

        if breached and sndl:
            risk = "CRITICAL"
            rationale = f"[{scenario_name.capitalize()} Scenario - Z={z} yrs] Inequality breached ({x} + {y} > {z}). Vulnerable to Store-Now-Decrypt-Later (SNDL)."
        elif breached:
            risk = base_severity
            rationale = f"[{scenario_name.capitalize()} Scenario - Z={z} yrs] Inequality breached ({x} + {y} > {z}). Remediation required."
        else:
            risk = "MEDIUM"
            rationale = f"[{scenario_name.capitalize()} Scenario - Z={z} yrs] Inequality holds ({x} + {y} <= {z})."

        return MoscaEvaluation(
            asset_id=f"{getattr(asset, 'asset_id', 'unknown')}-{scenario_name}", algorithm=algo_str,
            shelf_life_x=x, migration_time_y=y, quantum_threshold_z=z,
            is_inequality_breached=breached, risk_level=risk,
            sndl_vulnerable=sndl, recommended_pqc_replacement=replacement or "ML-KEM-768",
            rationale=rationale, scenario_name=scenario_name
        )

    def evaluate_asset(self, asset: NormalizedCryptoAsset, total_repository_loc: int = 10000, target_dir: Optional[Any] = None) -> Dict[str, MoscaEvaluation]:
        evaluations = {}
        for scenario_name, target_year in self.scenarios.items():
            evals = self.evaluate_asset_for_scenario(asset, scenario_name, target_year, total_repository_loc, target_dir)
            evaluations[evals.asset_id] = evals
        return evaluations

    def evaluate_batch(self, assets: List[NormalizedCryptoAsset], target_dir: Optional[Any] = None, excluded_dirs: Optional[List[str]] = None) -> Dict[str, MoscaEvaluation]:
        total_repo_loc = count_codebase_loc(target_dir, excluded_dirs)
        batch_evals = {}
        for asset in assets:
            scenario_results = self.evaluate_asset(asset, total_repo_loc, target_dir)
            batch_evals.update(scenario_results)
        return batch_evals