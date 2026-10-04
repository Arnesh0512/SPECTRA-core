"""
spectra.cli
================
Interactive Terminal User Interface (TUI) command-line interface for Spectra.
Guides users through scan parameters, executes domain discovery with progress bars,
evaluates Mosca quantum risk across scenarios, and generates CycloneDX 1.6 CBOMs.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import os
import shutil
import socket
import subprocess
import sys
import time
import webbrowser

from rich.align import Align
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
import typer

from spectra.config import (
    NetworkConfig,
    OutputConfig,
    ScanConfig,
    ScannerToggles,
    ScanTargets,
    SourceScannerConfig,
)
from spectra.engine import CryptoAnalysisEngine
from spectra.scanners import MasterScanner, ScanResults
from spectra.utils.logger import (
    BANNER,
    console,
    log_error,
    log_header,
    log_info,
    log_step,
    log_success,
    log_warning,
)
from spectra.utils.docker_client import DockerContainerClient

app = typer.Typer(
    name="spectra",
    help="Enterprise Multi-Domain Cryptographic Inventory & CycloneDX 1.6 CBOM Generator",
    add_completion=False,
)

def _is_server_listening(host: str = "127.0.0.1", port: int = 3000) -> bool:
    """Checks if a TCP port is currently open and responding."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            s.connect((host, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _ensure_visualizer_running(cbom_path: Path, port: int = 3000) -> Optional[str]:
    """Ensures the Spectra CBOM Web Visualizer server is running in the background."""
    if _is_server_listening("127.0.0.1", port):
        return f"http://localhost:{port}"

    candidate_server_paths = [
        Path(__file__).resolve().parent.parent / "web" / "server.js",
        Path.cwd() / "web" / "server.js",
        Path("/app/web/server.js"),
        Path("C:/Users/Arnesh/spectra/web/server.js"),
    ]
    server_js = next((p for p in candidate_server_paths if p.exists()), None)
    if not server_js:
        return None

    node_bin = shutil.which("node")
    if not node_bin:
        return None

    try:
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

        env = os.environ.copy()
        env["CBOM_PATH"] = str(cbom_path.resolve())

        subprocess.Popen(
            [node_bin, str(server_js), str(port), str(cbom_path.resolve())],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            env=env,
        )
        for _ in range(15):
            time.sleep(0.1)
            if _is_server_listening("127.0.0.1", port):
                break
    except Exception:
        pass

    return f"http://localhost:{port}"


# High-tech Cyber/Quantum Banner Art
CYBER_BANNER = r"""
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
"""


def _render_hero_banner(version: str = "1.0.0") -> None:
    """Renders the state-of-the-art quantum/cyber brand banner with system telemetry."""
    header_text = Text(CYBER_BANNER, style="bold cyan")
    full_form = Text.from_markup(
        "[bold bright_cyan]S[/bold bright_cyan][white]ystem for [/white]"
        "[bold bright_cyan]P[/bold bright_cyan][white]ost-quantum [/white]"
        "[bold bright_cyan]E[/bold bright_cyan][white]ncryption, [/white]"
        "[bold bright_cyan]C[/bold bright_cyan][white]ryptography with [/white]"
        "[bold bright_cyan]TR[/bold bright_cyan][white]acing & [/white]"
        "[bold bright_cyan]A[/bold bright_cyan][white]nalysis[/white]"
    )
    sub_title = Text("Enterprise Multi-Domain Cryptographic Inventory & CBOM Synthesis Engine", style="italic dim white")
    badges = Text.from_markup(
        "[bold cyan]⚡ CYCLONEDX 1.6[/bold cyan]  │  "
        "[bold magenta]⚛ NIST PQC (FIPS 203/204/205)[/bold magenta]  │  "
        "[bold yellow]⌛ MOSCA QUANTUM RISK[/bold yellow]  │  "
        "[bold green]🛡️  POST-QUANTUM ASSURANCE[/bold green]"
    )
    content = Align.center(Text.assemble(header_text, "\n", full_form, "\n\n", sub_title, "\n\n", badges))
    panel = Panel(
        content,
        box=box.ROUNDED,
        border_style="bright_blue",
        padding=(1, 2),
        title=f"[bold bright_cyan] SPECTRA v{version} [/bold bright_cyan]",
        subtitle="[dim white]System Status: Operational • Host Architecture: Multi-Domain AST & Dynamic Recon[/dim white]",
    )
    console.print()
    console.print(panel)


def _render_step_card(step_num: int, total_steps: int, title: str, subtitle: str, icon: str) -> None:
    """Renders a visually appealing step header card with icons and breadcrumb indicator."""
    header = Text()
    header.append(f"{icon} ", style="bold bright_cyan")
    header.append(f"STEP {step_num:02d}/{total_steps:02d}: ", style="bold yellow")
    header.append(title.upper(), style="bold bright_white")

    card = Panel(
        Text(subtitle, style="dim white"),
        title=header,
        title_align="left",
        box=box.ROUNDED,
        border_style="bright_blue",
        padding=(0, 2),
    )
    console.print()
    console.print(card)


def _render_preflight_dashboard(config_dict: Dict[str, Any]) -> None:
    """Renders an interactive Mission Manifest dashboard prior to executing scans."""
    left_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    left_table.add_column("Key", style="bold cyan", width=18)
    left_table.add_column("Value", style="bright_white")
    left_table.add_row("📂 Target Path", f"[bold bright_white]{config_dict['target_dir']}[/bold bright_white]")
    left_table.add_row("📄 CBOM Destination", f"[bold green]{config_dict['output_file']}[/bold green]")
    left_table.add_row("🛡️ Exclusions ", f"[dim]{config_dict['excluded_count']} directories[/dim]")
    left_table.add_row("🌐 Remote Targets", f"{len(config_dict['endpoints'])} endpoint(s)")

    right_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    right_table.add_column("Module", style="white")
    right_table.add_column("Status", justify="right")

    for mod, enabled in config_dict["modules"].items():
        status = "[bold green]● ACTIVE[/bold green]" if enabled else "[dim red]○ DISABLED[/dim red]"
        right_table.add_row(mod, status)

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(left_table, title="[bold cyan]TARGET GEOMETRY[/bold cyan]", box=box.ROUNDED, border_style="cyan"),
        Panel(right_table, title="[bold magenta]SCANNER MATRIX[/bold magenta]", box=box.ROUNDED, border_style="magenta"),
    )

    wrapper = Panel(
        grid,
        title="[bold bright_white]⚡ PRE-FLIGHT RECONNAISSANCE MANIFEST ⚡[/bold bright_white]",
        box=box.DOUBLE,
        border_style="bright_cyan",
        padding=(0, 1),
    )
    console.print()
    console.print(wrapper)


def _render_kpi_cards(findings_count: int, assets_count: int, links_count: int, breached_count: int) -> None:
    """Renders 4 high-contrast KPI metric cards across discovery and risk dimensions."""
    c1 = Panel(
        Align.center(f"[bold bright_cyan]{findings_count:,}[/bold bright_cyan]\n[dim white]Raw Telemetry Findings[/dim white]"),
        title="[cyan]FINDINGS[/cyan]",
        box=box.ROUNDED,
        border_style="cyan",
    )
    c2 = Panel(
        Align.center(f"[bold bright_green]{assets_count:,}[/bold bright_green]\n[dim white]Normalized CBOM Components[/dim white]"),
        title="[green]CBOM ASSETS[/green]",
        box=box.ROUNDED,
        border_style="green",
    )
    c3 = Panel(
        Align.center(f"[bold bright_yellow]{links_count}[/bold bright_yellow]\n[dim white]Cross-Domain Linkages[/dim white]"),
        title="[yellow]CORRELATIONS[/yellow]",
        box=box.ROUNDED,
        border_style="yellow",
    )
    c4 = Panel(
        Align.center(f"[bold red]{breached_count:,}[/bold red]\n[bold bright_red]SNDL Exposed (CRITICAL)[/bold bright_red]"),
        title="[red]MOSCA BREACHES[/red]",
        box=box.ROUNDED,
        border_style="red",
    )
    console.print()
    console.print(Columns([c1, c2, c3, c4], expand=True))


@app.command()
def scan(
    fail_on_critical: bool = typer.Option(
        False,
        "--fail-on-critical",
        help="Return a non-zero exit code if CRITICAL vulnerabilities or breached Mosca inequalities are detected.",
    ),
    container: Optional[str] = typer.Option(
        None,
        "--container",
        "-c",
        help="Target running Docker container name or ID to scan directly via Docker socket.",
    ),
    path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Target perimeter directory path inside container or host (default: container working directory or current directory).",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination CBOM artifact JSON file path (default: cbom.json).",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive mode: accept all defaults automatically.",
    ),
    ports: Optional[str] = typer.Option(
        None,
        "--ports",
        help="Target port(s) for localhost or container to scan (comma-separated, e.g. 443, 8443).",
    ),
    endpoints_opt: Optional[str] = typer.Option(
        None,
        "--endpoints",
        "-e",
        help="Target remote domain endpoints (comma-separated, supports multi-port syntax like domain:443,8443).",
    ),
    include_system_certs: Optional[bool] = typer.Option(
        None,
        "--include-system-certs/--skip-system-certs",
        help="Include preinstalled OS root CA trust store (Linux /etc/ssl/certs, Windows Root Store, macOS Keychain). Default is False (skipped).",
    ),
) -> None:
    """Run an interactive TUI wizard to configure and execute a multi-domain cryptographic scan."""
    _render_hero_banner()

    docker_client = DockerContainerClient()
    is_docker_available = docker_client.is_available()

    target_container = container
    target_path: Path
    container_internal_path = path

    # --- STEP 1: Target & Output Configuration ---
    if target_container:
        _render_step_card(
            1, 4,
            "Target & Output Configuration",
            f"Container Mode Active: Scanning Docker container '{target_container}'.",
            "🐳",
        )
        if not is_docker_available:
            console.print("[bold red]✖ Docker socket (/var/run/docker.sock) is not accessible![/bold red]")
            console.print("[dim]Ensure Docker socket is mounted via '-v /var/run/docker.sock:/var/run/docker.sock'[/dim]")
            raise typer.Exit(1)

        try:
            c_info = docker_client.get_container_info(target_container)
        except Exception as e:
            console.print(f"[bold red]✖ Failed to locate container '{target_container}': {e}[/bold red]")
            raise typer.Exit(1)

        c_status = c_info.get("State", {}).get("Status", "unknown")
        c_image = c_info.get("Config", {}).get("Image", "unknown")
        env_vars = dict(e.split("=", 1) for e in c_info.get("Config", {}).get("Env", []) if "=" in e)
        c_user = c_info.get("Config", {}).get("User", "")
        c_home = env_vars.get("HOME")
        if not c_home:
            c_home = f"/home/{c_user}" if (c_user and c_user != "root") else "/root"
        console.print(f"      [bold cyan]• Target Container:[/bold cyan] [bold bright_white]{target_container}[/bold bright_white] ({c_status})")
        console.print(f"      [bold cyan]• Base Image:[/bold cyan] [dim]{c_image}[/dim]")

        working_dir = c_info.get("Config", {}).get("WorkingDir") or ""
        default_target = working_dir if working_dir else (c_home or "/opt/nexis")
        if not container_internal_path:
            if yes:
                container_internal_path = default_target
            else:
                container_internal_path = Prompt.ask(
                    "      [dim]↳ Enter directory path inside container[/dim]",
                    default=default_target,
                    show_default=False,
                )

        console.print(f"      [bold yellow]⚡ Resolving container perimeter {target_container}:{container_internal_path}...[/bold yellow]")
        try:
            target_path, _ = docker_client.resolve_container_perimeter(target_container, container_internal_path)
            console.print(f"      [bold green]✔ Container perimeter bound to:[/bold green] [bold bright_white]{target_path}[/bold bright_white]\n")
        except Exception as e:
            console.print(f"[bold red]✖ Container perimeter extraction failed: {e}[/bold red]")
            raise typer.Exit(1)
    else:
        _render_step_card(
            1, 4,
            "Target & Output Configuration",
            "Define target perimeter directory and destination CBOM artifact path.",
            "📂",
        )
        console.print("  [bold cyan]1.1 Target Perimeter Path[/bold cyan]")
        prompt_label = "      [dim]↳ Enter directory path or container name[/dim]" if is_docker_available else "      [dim]↳ Enter directory path[/dim]"
        target_str = path if (path and yes) else Prompt.ask(prompt_label, default=".", show_default=False)

        def _path_does_not_exist(p_str: str) -> bool:
            try:
                return not Path(p_str).exists()
            except (PermissionError, OSError):
                return False

        if is_docker_available and (target_str.startswith("container:") or target_str.startswith("docker:")):
            target_container = target_str.split(":", 1)[1]
            c_int_path = None
            if ":" in target_container:
                target_container, c_int_path = target_container.split(":", 1)
            target_path, _ = docker_client.resolve_container_perimeter(target_container, c_int_path)
            console.print(f"      [bold green]✔ Container perimeter bound to:[/bold green] [bold bright_white]{target_path}[/bold bright_white]\n")
        elif is_docker_available and target_str != "." and _path_does_not_exist(target_str):
            try:
                c_info = docker_client.get_container_info(target_str)
                target_container = target_str
                c_env_vars = dict(e.split("=", 1) for e in c_info.get("Config", {}).get("Env", []) if "=" in e)
                c_user = c_info.get("Config", {}).get("User", "")
                c_int_path = c_env_vars.get("HOME") or (f"/home/{c_user}" if (c_user and c_user != "root") else "/root")
                target_path, _ = docker_client.resolve_container_perimeter(target_container, c_int_path)
                console.print(f"      [bold green]✔ Detected Docker container '{target_container}' bound to:[/bold green] [bold bright_white]{target_path}[/bold bright_white]\n")
            except Exception:
                target_path = Path(target_str).resolve()
                console.print(f"      [bold green]✔ Perimeter bound to:[/bold green] [bold bright_white]{target_path}[/bold bright_white]\n")
        else:
            target_path = Path(target_str).resolve()
            try:
                if not target_path.exists():
                    console.print(f"      [bold red]✖ Warning: Target path does not exist:[/bold red] [bright_white]{target_path}[/bright_white]\n")
                elif target_path.is_dir():
                    next(target_path.iterdir(), None)
            except PermissionError:
                console.print(f"\n      [bold red]✖ Permission denied accessing target directory:[/bold red] [bold bright_white]{target_path}[/bold bright_white]")
                console.print("      [dim yellow]Cause: Current user or container user lacks read/execute permissions on this path.[/dim yellow]")
                console.print("      [bold cyan]Solution:[/bold cyan] Add [bold bright_white]-u root[/bold bright_white] to your docker run command:\n")
                console.print(f"      [bold green]docker run -it --rm -u root -p 3000:3000 -v /:/scan -v /mnt/c/Users/Arnesh/Desktop/:/output spectra scan[/bold green]\n")
                raise typer.Exit(1)
            console.print(f"      [bold green]✔ Perimeter bound to:[/bold green] [bold bright_white]{target_path}[/bold bright_white]\n")

    # Destination CBOM Artifact Path (Default: Container Home Directory)
    default_out = str(Path.home() / "cbom.json")
    if output:
        output_path = Path(output).expanduser().resolve()
    elif yes:
        output_path = Path(default_out).resolve()
    else:
        console.print("  [bold cyan]1.2 Destination CBOM Artifact[/bold cyan]")
        output_str = Prompt.ask(
            "      [dim]↳ Enter output JSON filename[/dim]",
            default=default_out,
            show_default=False,
        )
        output_path = Path(output_str).expanduser().resolve()

    if output_path.is_dir():
        output_path = output_path / "cbom.json"
    elif output_path.suffix == "":
        output_path = output_path.with_suffix(".json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    console.print(f"      [bold green]✔ Output target designated:[/bold green] [bold bright_white]{output_path}[/bold bright_white]")

    # --- STEP 2 & 3: Exclusions and Scanner Matrix ---
    default_excludes = ".git, node_modules, vendor, target, dist, build, .venv, venv, __pycache__"
    if yes:
        excluded_dirs = [d.strip() for d in default_excludes.split(",") if d.strip()]
        scan_source = True
        scan_deps = True
        scan_certs = True
        scan_system_certs = False if include_system_certs is None else include_system_certs
        scan_binaries = True
        scan_hardware = True
        scan_runtime_artifacts = False
        enable_artifacts = True
        scan_terraform = True
        scan_docker = True
        scan_cloud_hsm = True
        enable_infra = True
        endpoints = []
        enable_network = True
        from spectra.utils.system_paths import parse_endpoint_targets
        if target_container:
            c_net = docker_client.get_container_network_ports(target_container)
            c_ip = c_net.get("ip")
            exposed = c_net.get("exposed_ports", [])
            bindings = c_net.get("port_bindings", {})
            target_ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()] if ports else [p for p in exposed if p in [443, 8443, 8080, 8444, 9443, 4443]] or [443, 8443]
            for p_int in target_ports:
                if c_ip:
                    endpoints.append(f"{c_ip}:{p_int}")
                if p_int in bindings:
                    for hp in bindings[p_int]:
                        endpoints.append(f"localhost:{hp}")
                elif not c_ip:
                    endpoints.append(f"localhost:{p_int}")
        elif ports:
            for p_str in ports.split(","):
                if p_str.strip().isdigit():
                    endpoints.append(f"localhost:{int(p_str.strip())}")
        if endpoints_opt:
            endpoints.extend(parse_endpoint_targets(endpoints_opt))
        # Deduplicate
        seen_eps = set()
        endpoints = [e for e in endpoints if not (e in seen_eps or seen_eps.add(e))]
    else:
        _render_step_card(
            2, 4,
            "Source Exclusions & Perimeter Filters",
            "Configure directories to bypass during AST tree-walking and ripgrep token filtering.",
            "🛡️",
        )
        console.print("  [bold cyan]2.1 Directory Exclusions[/bold cyan] [dim](comma-separated)[/dim]")
        exclude_input = Prompt.ask(
            "      [dim]↳ Excluded folders[/dim]",
            default=default_excludes,
        )
        excluded_dirs = [d.strip() for d in exclude_input.split(",") if d.strip()]
        preview_excludes = "  ".join([f"[dim on grey23] {d} [/dim on grey23]" for d in excluded_dirs[:8]])
        if len(excluded_dirs) > 8:
            preview_excludes += f"  [dim]+{len(excluded_dirs) - 8} more[/dim]"
        console.print(f"      [bold green]✔ Filters active ({len(excluded_dirs)}):[/bold green] {preview_excludes}")

        _render_step_card(
            3, 4,
            "Reconnaissance Scanner Matrix",
            "Enable or disable individual inspection modules across discovery domains.",
            "⚙️",
        )

        console.print("  [bold underline bright_cyan]Domain 1: Source Code & Call-Graph Inspection[/bold underline bright_cyan]")
        scan_source = Confirm.ask("    [bright_white]• Scan codebase source files (AST & Token Analysis)[/bright_white]", default=True)
        scan_deps = Confirm.ask("    [bright_white]• Scan Dependency manifests (SBOM & lockfiles)[/bright_white]", default=False)

        console.print("\n  [bold underline magenta]Domain 2: Infrastructure & Cloud Key Management[/bold underline magenta]")
        scan_terraform = Confirm.ask("    [bright_white]• Scan Terraform / IaC configurations (.tf, CloudFormation)[/bright_white]", default=True)
        scan_docker = Confirm.ask("    [bright_white]• Scan Docker container files (Dockerfile, Compose)[/bright_white]", default=True)
        scan_cloud_hsm = Confirm.ask("    [bright_white]• Scan Cloud KMS / HSM configurations (AWS/Azure/GCP)[/bright_white]", default=True)
        enable_infra = scan_terraform or scan_docker or scan_cloud_hsm

        console.print("\n  [bold underline blue]Domain 3: Network Protocols & TLS Perimeter[/bold underline blue]")
        enable_network = Confirm.ask("    [bright_white]• Scan live network TLS endpoints & web servers?[/bright_white]", default=True)
        endpoints = []
        if enable_network:
            from spectra.utils.system_paths import parse_endpoint_targets

            # 3.1 Localhost / Container Port Configuration (Prompted before remote endpoints)
            console.print("  [bold cyan]3.1 Localhost & Container Port Discovery[/bold cyan]")
            if target_container:
                c_net = docker_client.get_container_network_ports(target_container)
                c_ip = c_net.get("ip")
                exposed = c_net.get("exposed_ports", [])
                bindings = c_net.get("port_bindings", {})

                is_running = c_net.get("is_running", True)
                status_str = c_net.get("status", "running")

                if not is_running:
                    console.print(f"      [bold yellow]⚠ Notice:[/bold yellow] Target container '[bold bright_white]{target_container}[/bold bright_white]' is currently [bold red]{status_str}[/bold red].")
                    console.print(f"      [dim]Run 'docker start {target_container}' to enable direct container IP network auditing.[/dim]")

                if c_ip:
                    console.print(f"      [bold cyan]• Target Container:[/bold cyan] [bold bright_white]{target_container}[/bold bright_white] ([bold bright_green]{c_ip}[/bold bright_green])")
                else:
                    console.print(f"      [bold cyan]• Target Container:[/bold cyan] [bold bright_white]{target_container}[/bold bright_white]")
                if exposed:
                    console.print(f"      [dim]• Detected Exposed Port(s): {', '.join(map(str, exposed))}[/dim]")
                if bindings:
                    bound_desc = [f"localhost:{hp} -> {cp}" for cp, hps in bindings.items() for hp in hps]
                    console.print(f"      [dim]• Host-Mapped Port(s): {', '.join(bound_desc)}[/dim]")

                detected_tls = [str(p) for p in exposed if p in [443, 8443, 8080, 8444, 9443, 4443]]
                default_ports_str = ", ".join(detected_tls) if detected_tls else "443, 8443"

                if yes and ports is None:
                    target_ports_input = default_ports_str
                elif ports is not None:
                    target_ports_input = ports
                else:
                    target_ports_input = Prompt.ask(
                        f"      [dim]↳ Enter port(s) to scan for container '{target_container}' (comma-separated, e.g., 443, 8443)[/dim]",
                        default=default_ports_str,
                    )

                for p_str in target_ports_input.split(","):
                    p_clean = p_str.strip()
                    if p_clean.isdigit():
                        p_int = int(p_clean)
                        if c_ip:
                            endpoints.append(f"{c_ip}:{p_int}")
                        if p_int in bindings:
                            for hp in bindings[p_int]:
                                endpoints.append(f"localhost:{hp}")
                        elif not c_ip:
                            endpoints.append(f"localhost:{p_int}")
            else:
                # Host / Local machine mode
                if yes and ports is None:
                    target_ports_input = "443, 8443"
                elif ports is not None:
                    target_ports_input = ports
                else:
                    target_ports_input = Prompt.ask(
                        "      [dim]↳ Enter port(s) to scan on localhost (comma-separated, e.g., 443, 8443, or empty to skip)[/dim]",
                        default="443, 8443",
                    )

                for p_str in target_ports_input.split(","):
                    p_clean = p_str.strip()
                    if p_clean.isdigit():
                        endpoints.append(f"localhost:{int(p_clean)}")

            if endpoints:
                console.print(f"      [bold green]✔ Registered local/container target(s):[/bold green] [dim]{', '.join(endpoints)}[/dim]\n")

            # 3.2 Remote Domain Endpoints (supports multi-port: domain:443,8443 or domain:443/8443)
            console.print("  [bold cyan]3.2 Remote Domain Endpoints[/bold cyan]")
            console.print("      [dim]Tip: You can specify multiple ports (e.g. 'domain:443,8443' or 'domain:443, 8443')[/dim]")
            if yes and endpoints_opt is None:
                endpoints_input = ""
            elif endpoints_opt is not None:
                endpoints_input = endpoints_opt
            else:
                endpoints_input = Prompt.ask(
                    "      [dim]↳ Enter remote domain endpoints (comma-separated, e.g., example.com:443)[/dim]",
                    default="",
                )

            if endpoints_input.strip():
                domain_endpoints = parse_endpoint_targets(endpoints_input)
                endpoints.extend(domain_endpoints)

            # Deduplicate endpoints preserving order
            seen_eps = set()
            deduped_eps = []
            for ep in endpoints:
                if ep not in seen_eps:
                    seen_eps.add(ep)
                    deduped_eps.append(ep)
            endpoints = deduped_eps

            console.print(f"      [bold green]✔ Total network targets registered: {len(endpoints)} endpoint(s).[/bold green]")

        console.print("\n  [bold underline yellow]Domain 4: Cryptographic Artifacts & Binaries[/bold underline yellow]")
        scan_certs = Confirm.ask("    [bright_white]• Scan X.509 Certificates & Private Keys (.pem, .crt, .key)[/bright_white]", default=True)
        scan_system_certs = False
        if scan_certs:
            if include_system_certs is not None:
                scan_system_certs = include_system_certs
            else:
                from spectra.utils.system_paths import get_os_trust_store_label
                trust_label = get_os_trust_store_label(target_path)
                scan_system_certs = Confirm.ask(
                    f"      [dim]↳ Include preinstalled OS root CA trust store ({trust_label})?[/dim]",
                    default=False,
                )
        scan_binaries = Confirm.ask("    [bright_white]• Scan Binary executables & shared libraries (.so, .dll, ELF)[/bright_white]", default=True)
        scan_hardware = Confirm.ask("    [bright_white]• Scan Hardware cryptographic devices (TPM, HSM, CPU instruction sets)[/bright_white]", default=True)
        scan_runtime_artifacts = Confirm.ask("    [bright_white]• Scan Active process memory & dynamic runtime packages[/bright_white]", default=False)
        enable_artifacts = scan_certs or scan_binaries or scan_hardware or scan_runtime_artifacts

    # --- Pre-Flight Summary Manifest ---
    preflight_data = {
        "target_dir": str(target_path),
        "output_file": str(output_path.name),
        "excluded_count": len(excluded_dirs),
        "endpoints": endpoints,
        "modules": {
            "Source Code AST": scan_source,
            "Package Dependencies": scan_deps,
            "Terraform & IaC": scan_terraform,
            "Containers / Docker": scan_docker,
            "Cloud KMS / HSM": scan_cloud_hsm,
            "Remote TLS Network": enable_network,
            "X.509 Certs & Keys": scan_certs,
            "OS Root CA Store": scan_system_certs if scan_certs else False,
            "Binaries & DLLs": scan_binaries,
            "Hardware (TPM/HSM)": scan_hardware,
            "Process Runtime": scan_runtime_artifacts,
        },
    }
    _render_preflight_dashboard(preflight_data)

    # --- Build ScanConfig Programmatically ---
    config = ScanConfig(
        scan_targets=ScanTargets(
            project_root=str(target_path),
            container_target=target_container,
            domains=endpoints,
            nginx_config_paths=[],
        ),
        scanners=ScannerToggles(
            enable_source=scan_source,
            enable_artifacts=enable_artifacts,
            enable_runtime=scan_runtime_artifacts,
            enable_infrastructure=enable_infra,
            enable_network=enable_network,
            scan_dependencies=scan_deps,
            scan_certificates=scan_certs,
            include_system_certs=scan_system_certs,
            scan_docker=scan_docker,
            scan_hardware=scan_hardware,
            scan_binaries=scan_binaries,
            scan_terraform=scan_terraform,
        ),
        source_scanner=SourceScannerConfig(
            use_ripgrep=True,
            excluded_directories=excluded_dirs,
        ),
        network=NetworkConfig(endpoints=endpoints),
        output=OutputConfig(output_file=str(output_path)),
    )

    if hasattr(config, "aws") and config.aws:
        config.aws.enabled = scan_cloud_hsm
    if hasattr(config, "azure") and config.azure:
        config.azure.enabled = scan_cloud_hsm
    if hasattr(config, "gcp") and config.gcp:
        config.gcp.enabled = scan_cloud_hsm

    # --- Pre-resolve X completely outside active progress context ---
    from spectra.engine.mosca import MoscaRiskEngine
    try:
        MoscaRiskEngine().get_resolved_shelf_life_x(target_path)
    except (PermissionError, OSError):
        pass

    # --- STEP 4: Executing Multi-Domain Reconnaissance & CBOM Pipeline ---
    _render_step_card(
        4, 4,
        "Multi-Domain Reconnaissance & Synthesis",
        "Executing unified discovery, correlation, Mosca evaluation, and CBOM generation.",
        "🚀",
    )

    scanner = MasterScanner(config)
    engine = CryptoAnalysisEngine(config)

    from rich.markup import escape

    progress = Progress(
        SpinnerColumn("aesthetic", style="bold cyan"),
        TextColumn("{task.description}"),
        BarColumn(bar_width=32, style="grey23", complete_style="bold cyan", finished_style="bold green"),
        TaskProgressColumn(text_format="[bold bright_cyan]{task.percentage:>3.0f}%[/bold bright_cyan]"),
        TimeElapsedColumn(),
        console=console,
    )
    stage_task = progress.add_task("[bold white]Phase 1/5: Multi-Domain Reconnaissance...[/bold white]", total=100)

    term_width = console.width if (console.width and console.width >= 60) else 100
    col1_w = 10
    col2_w = 20
    col3_w = max(24, term_width - 40)

    type_colors = {
        "source code": "bright_cyan",
        "depedency": "bright_yellow",
        "dependency": "bright_yellow",
        "certifcate": "bright_green",
        "certificate": "bright_green",
        "nginx-cert": "bright_green",
        "terraform-cert": "bright_green",
        "terra-cert": "bright_green",
        "iac-cert": "bright_green",
        "k8s-cert": "bright_green",
        "docker-cert": "bright_green",
        "system ca": "dim cyan",
        "binary": "bright_magenta",
        "container": "bright_blue",
        "dockerfile": "bright_blue",
        "docker": "bright_blue",
        "terraform": "bright_magenta",
        "cloud": "bright_cyan",
        "aws": "bright_cyan",
        "azure": "bright_blue",
        "gcloud": "bright_yellow",
        "kubernetes": "bright_cyan",
        "cloudformation": "bright_magenta",
        "compose": "bright_blue",
        "hardware": "bright_red",
        "infra": "bright_cyan",
        "iac": "bright_cyan",
        "manifest": "dim white",
        "cbom": "dim cyan",
        "config": "dim white",
        "nginx": "bright_yellow",
        "ssh": "bright_yellow",
        "protocol": "bright_cyan",
        "ipsec": "bright_cyan",
        "network endpoint": "bright_green",
        "endpoint": "bright_green",
    }

    with progress:
        header_printed = False

        def on_recon_progress(desc: str, pct: float, item_info: Optional[Dict[str, Any]] = None) -> None:
            nonlocal header_printed
            # stage_task reflects the current reconnaissance phase progress (0% -> 100%)
            import re
            padded = f"{desc:<62}"
            # Style [language] tags in bold cyan with escaped brackets so Rich doesn't strip them
            formatted_desc = re.sub(
                r'\[([a-zA-Z0-9_\-\+]+)\]',
                r'[bold cyan]\[\1][/bold cyan]',
                padded
            )
            progress.update(stage_task, completed=pct, description=f"[bold white]{formatted_desc}[/bold white]")

            if item_info:
                seq = str(item_info.get("seq", ""))
                itype = str(item_info.get("type", ""))
                filename = str(item_info.get("filename", ""))
                raw_loc = str(item_info.get("location", ""))
                from spectra.utils.system_paths import format_display_path
                location = format_display_path(raw_loc, target_path) if raw_loc else ""
            else:
                m_dep = re.search(r"Dependency \((\d+/\d+)\) \[([^\]]+)\] (.+)", desc)
                m_ast = re.search(r"AST Parsing \((\d+/\d+)\) \[([^\]]+)\] (.+)", desc)
                if m_dep:
                    seq = m_dep.group(1)
                    itype = "depedency"
                    filename = m_dep.group(3).strip()
                    location = ""
                elif m_ast:
                    seq = m_ast.group(1)
                    itype = "source code"
                    filename = m_ast.group(3).strip()
                    location = ""
                else:
                    return

            if not header_printed:
                progress.console.print(f"[cyan]╭{'─' * (col1_w + 2)}┬{'─' * (col2_w + 2)}┬{'─' * (col3_w + 2)}╮[/cyan]")
                progress.console.print(f"[cyan]│[/cyan] [bold bright_cyan]{'Seq':^{col1_w}}[/bold bright_cyan] [cyan]│[/cyan] [bold bright_cyan]{'Type':<{col2_w}}[/bold bright_cyan] [cyan]│[/cyan] [bold bright_cyan]{'Filename & Location':<{col3_w}}[/bold bright_cyan] [cyan]│[/cyan]")
                progress.console.print(f"[cyan]├{'─' * (col1_w + 2)}┼{'─' * (col2_w + 2)}┼{'─' * (col3_w + 2)}┤[/cyan]")
                header_printed = True

            color = type_colors.get(itype.lower())
            if not color:
                if itype.lower().endswith("-cert"):
                    color = "bright_green"
                else:
                    color = "bright_white"
            esc_fn = escape(filename)
            esc_loc = escape(location)
            raw_col3 = f"{filename}  {location}" if location else filename

            if len(raw_col3) > col3_w:
                if location:
                    avail_loc = col3_w - len(filename) - 5
                    if avail_loc > 10:
                        trunc_loc = location[:avail_loc] + "..."
                        styled_col3 = f"[bold white]{esc_fn}[/bold white]  [dim white]{escape(trunc_loc)}[/dim white]"
                    else:
                        trunc_raw = raw_col3[:col3_w - 3] + "..."
                        styled_col3 = f"[bold white]{escape(trunc_raw)}[/bold white]"
                else:
                    styled_col3 = f"[bold white]{escape(raw_col3[:col3_w - 3])}...[/bold white]"
                pad = ""
            else:
                if location:
                    styled_col3 = f"[bold white]{esc_fn}[/bold white]  [dim white]{esc_loc}[/dim white]"
                else:
                    styled_col3 = f"[bold white]{esc_fn}[/bold white]"
                pad = " " * (col3_w - len(raw_col3))

            row = (
                f"[cyan]│[/cyan] [bold cyan]{seq:^{col1_w}}[/bold cyan] "
                f"[cyan]│[/cyan] [{color}]{itype:<{col2_w}}[/{color}] "
                f"[cyan]│[/cyan] {styled_col3}{pad} "
                f"[cyan]│[/cyan]"
            )
            progress.console.print(row)

        # 1. Multi-Domain Reconnaissance
        results: ScanResults = scanner.scan_all(
            target_dir=target_path,
            endpoints=endpoints,
            progress_callback=on_recon_progress,
        )
        if header_printed:
            progress.console.print(f"[cyan]╰{'─' * (col1_w + 2)}┴{'─' * (col2_w + 2)}┴{'─' * (col3_w + 2)}╯[/cyan]")

        progress.update(stage_task, completed=100, description="[bold green]✔ Phase 1/5: Reconnaissance Complete[/bold green]")
        progress.console.print(f"  [bold green]✔[/bold green] Discovered {results.total_count:,} raw cryptographic telemetry findings.")

        if results.total_count == 0:
            log_warning("No cryptographic primitives, artifacts, or configs detected in scan scope.")
            return

        # 2. Canonical Normalization
        progress.update(stage_task, description="[bold cyan]Phase 2/5: Canonical Asset Normalization...[/bold cyan]", completed=15)
        normalized_assets = engine.normalizer.normalize_batch(results.all_findings)
        progress.update(stage_task, completed=100)
        progress.console.print(f"  [bold green]✔[/bold green] Successfully normalized {len(normalized_assets):,} cryptographic assets.")

        # 3. Cross-Domain Correlation
        progress.update(stage_task, description="[bold yellow]Phase 3/5: Cross-Domain Blast Radius Correlation...[/bold yellow]", completed=20)
        correlated_assets = engine.correlator.correlate(normalized_assets)
        correlated_links = sum(len(ca.cross_domain_links) for ca in correlated_assets)
        progress.update(stage_task, completed=100)
        progress.console.print(f"  [bold green]✔[/bold green] Established {correlated_links} cross-domain links across {len(correlated_assets):,} composite assets.")

        # 4. Mosca Multi-Scenario Quantum Risk Simulation
        progress.update(stage_task, description="[bold magenta]Phase 4/5: Mosca Quantum Risk Simulation (3 Scenarios)...[/bold magenta]", completed=20)
        mosca_evals = engine.mosca_engine.evaluate_batch(
            normalized_assets,
            target_dir=target_path,
            excluded_dirs=excluded_dirs,
        )
        breached_count = sum(1 for m in mosca_evals.values() if m.is_inequality_breached)
        progress.update(stage_task, completed=100)
        progress.console.print(f"  [bold green]✔[/bold green] Evaluated {len(mosca_evals):,} scenario-asset combinations ({breached_count:,} breaches).")

        # 5. CycloneDX 1.6 CBOM Synthesis & Serialization
        progress.update(stage_task, description="[bold bright_green]Phase 5/5: CycloneDX 1.6 CBOM Synthesis...[/bold bright_green]", completed=25)
        cbom = engine.cbom_builder.build_cbom(
            correlated_assets=correlated_assets,
            mosca_evaluations=mosca_evals,
        )
        written_path = engine.cbom_builder.save_cbom(cbom, output_path)
        output_path = written_path
        progress.update(stage_task, completed=100)
        progress.console.print(f"  [bold green]✔[/bold green] CycloneDX 1.6 CBOM exported to: [bold bright_white]{written_path}[/bold bright_white]")

    # --- Render Executive KPI Cards ---
    _render_kpi_cards(results.total_count, len(normalized_assets), correlated_links, breached_count)

    # --- Render Enhanced Summary Tables ---
    _print_findings_summary(correlated_assets)
    _print_quantum_risk_summary(mosca_evals)

    # Format valid clickable RFC 8089 file URI (exactly 3 slashes)
    posix_path = output_path.resolve().as_posix()
    if posix_path.startswith("/mnt/c/"):
        file_uri = f"file:///C:/{posix_path[7:].lstrip('/')}"
    else:
        file_uri = f"file:///{posix_path.lstrip('/')}"

    # --- Render Final Artifact Completion Card ---
    file_size_kb = (output_path.stat().st_size / 1024.0) if output_path.exists() else 0.0
    completion_panel = Panel(
        Align.center(
            f"[bold bright_green]✔ CYCLONEDX 1.6 CRYPTOGRAPHIC BILL OF MATERIALS GENERATED[/bold bright_green]\n\n"
            f"[bright_white]Artifact File:[/bright_white] [bold bright_cyan underline][link={file_uri}]{output_path}[/link][/bold bright_cyan underline]  │  "
            f"[bright_white]Components:[/bright_white] [bold green]{len(correlated_assets):,}[/bold green]  │  "
            f"[bright_white]Size:[/bright_white] [bold yellow]{file_size_kb:.1f} KB[/bold yellow]  │  "
            f"[bright_white]Spec:[/bright_white] [bold magenta]CycloneDX 1.6[/bold magenta]"
        ),
        title="[bold bright_cyan] AUDIT ARTIFACT READY [/bold bright_cyan]",
        box=box.DOUBLE,
        border_style="bright_green",
        padding=(1, 2),
    )
    console.print()
    console.print(completion_panel)
    console.print(f"  📄 [bold green]CBOM Artifact Link:[/bold green] [bold bright_cyan underline][link={file_uri}]{output_path.resolve()}[/link][/bold bright_cyan underline]\n")

    # --- Launch / Connect Interactive CBOM Web Visualizer ---
    web_url = _ensure_visualizer_running(output_path, port=3000)
    if web_url:
        visualizer_panel = Panel(
            Align.center(
                f"[bold bright_cyan]🌐 INTERACTIVE CBOM & QUANTUM RISK WEB VISUALIZER[/bold bright_cyan]\n\n"
                f"[bright_white]Click to inspect full CBOM in browser:[/bright_white]  "
                f"[bold underline bright_yellow][link={web_url}]{web_url}[/link][/bold underline bright_yellow]\n"
                f"[bright_white]View Raw CBOM JSON (Browser/API):[/bright_white]      "
                f"[bold underline cyan][link={web_url}/api/cbom]{web_url}/api/cbom[/link][/bold underline cyan]\n\n"
                f"[dim bright_white]Executive KPIs • Inventory Explorer • Mosca Simulator • NIST PQC Compliance • Graph Topology[/dim bright_white]"
            ),
            title="[bold bright_green] LOCALHOST CONSOLE [/bold bright_green]",
            box=box.ROUNDED,
            border_style="bright_cyan",
            padding=(1, 2),
        )
        console.print(visualizer_panel)
        console.print(f"  🌐 [bold bright_cyan]Interactive Visualizer Link:[/bold bright_cyan] [bold underline bright_yellow][link={web_url}]{web_url}[/link][/bold underline bright_yellow]\n")
        if not yes:
            console.print("  [dim]Press Ctrl+C to shut down and exit...[/dim]\n")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[dim]Shutting down visualizer...[/dim]")
        else:
            time.sleep(0.5)

    # Check failure conditions
    critical_breaches = any(
        m.risk_level == "CRITICAL" for m in mosca_evals.values()
    ) or any(
        any(f.get("severity") == "CRITICAL" for f in a.primary_asset.security_findings)
        for a in correlated_assets
    )

    if fail_on_critical and critical_breaches:
        log_error("Critical cryptographic or quantum risks discovered. Exiting with status code 1.")
        sys.exit(1)


@app.command()
def mosca(
    target_year: int = typer.Option(
        2033,
        "--year",
        "-y",
        help="Target year for Cryptanalytically Relevant Quantum Computer (CRQC) realization.",
    ),
    shelf_life: int = typer.Option(
        7,
        "--shelf-life",
        "-x",
        help="Required data confidentiality shelf-life horizon (years).",
    ),
    migration_time: int = typer.Option(
        3,
        "--migration-time",
        "-m",
        help="Estimated time needed to complete post-quantum migration (years).",
    ),
) -> None:
    """Print an interactive Mosca Theorem inequality status report."""
    _render_hero_banner()

    current_year = 2026
    z = max(1, target_year - current_year)
    breached = (shelf_life + migration_time) > z

    table = Table(
        title="[bold bright_cyan]MOSCA INEQUALITY QUANTUM RISK MODEL (X + Y > Z)[/bold bright_cyan]",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_white",
        expand=True,
    )
    table.add_column("Parameter", style="cyan", width=22)
    table.add_column("Value", style="bold white", justify="center", width=14)
    table.add_column("Description", style="white")

    table.add_row("X (Shelf-Life)", f"{shelf_life} yrs", "Required data confidentiality horizon")
    table.add_row("Y (Migration Time)", f"{migration_time} yrs", "Time needed to re-engineer & deploy PQC")
    table.add_row("Z (Collapse Horizon)", f"{z} yrs", f"Years remaining until CRQC ({target_year})")
    table.add_row(
        "Inequality (X + Y > Z)",
        f"{shelf_life + migration_time} > {z}",
        "[bold red]✖ BREACHED (Store-Now-Decrypt-Later Threat)[/bold red]" if breached else "[bold green]✔ SECURE (Inequality Holds)[/bold green]",
    )

    console.print()
    console.print(table)
    if breached:
        log_error("Urgent Action Required: Classical key exchanges are vulnerable to Store-Now-Decrypt-Later (SNDL) attacks.")
    else:
        log_info("Inequality currently holds. Proactive quantum-safe roadmapping recommended.")


@app.command()
def version() -> None:
    """Display tool version and specification compliance."""
    _render_hero_banner()
    info_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, expand=True)
    info_table.add_column("Key", style="bold cyan", width=25)
    info_table.add_column("Value", style="bright_white")
    info_table.add_row("Engine Version", "1.0.0 (Quantum Edition)")
    info_table.add_row("CycloneDX Specification", "[bold green]1.6 (Cryptographic Properties CBOM)[/bold green]")
    info_table.add_row("Post-Quantum Cryptography", "[bold green]NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)[/bold green]")
    info_table.add_row("Quantum Threat Model", "[bold yellow]Mosca Inequality (X + Y > Z) Multi-Scenario[/bold yellow]")
    console.print()
    console.print(info_table)


@app.command()
def ui(
    cbom: Path = typer.Option(
        Path("C:/Users/Arnesh/Desktop/cbom.json"),
        "--cbom",
        "-c",
        help="Path to the CycloneDX 1.6 CBOM JSON file.",
    ),
    port: int = typer.Option(
        3000,
        "--port",
        "-p",
        help="Port to serve the interactive CBOM visualizer on.",
    ),
    open_browser: bool = typer.Option(
        True,
        "--open/--no-open",
        help="Automatically open the visualizer in default browser.",
    ),
) -> None:
    """Launch the interactive Spectra CBOM & Quantum Risk Web Visualizer."""
    _render_hero_banner()

    resolved_cbom = cbom
    if resolved_cbom.is_dir():
        resolved_cbom = resolved_cbom / "cbom.json"
    if not resolved_cbom.exists():
        candidates = [
            Path("cbom.json"),
            Path(os.path.expanduser("~")) / "Desktop" / "cbom.json",
            Path("C:/Users/Arnesh/Desktop/cbom.json"),
        ]
        for c in candidates:
            if c.exists():
                resolved_cbom = c
                break

    if not resolved_cbom.exists():
        log_error(f"CBOM file not found at '{cbom}'. Run 'spectra scan' first to generate a CBOM.")
        sys.exit(1)

    url = _ensure_visualizer_running(resolved_cbom, port=port)
    if not url:
        log_error("Could not launch web visualizer. Please ensure Node.js is installed.")
        sys.exit(1)

    panel = Panel(
        Align.center(
            f"[bold bright_cyan]SPECTRA CBOM VISUALIZER ONLINE[/bold bright_cyan]\n\n"
            f"[bright_white]Local Dashboard:[/bright_white]   [bold underline bright_yellow][link={url}]{url}[/link][/bold underline bright_yellow]\n"
            f"[bright_white]Ingested CBOM:[/bright_white]     [bold green]{resolved_cbom.resolve()}[/bold green]\n"
            f"[bright_white]REST API:[/bright_white]          [cyan]{url}/api/cbom[/cyan]\n\n"
            f"[dim bright_white]Features: Executive KPIs • Deep Inventory • Mosca Simulator • NIST PQC • Topology Graph[/dim bright_white]"
        ),
        title="[bold bright_green] WEB DASHBOARD [/bold bright_green]",
        box=box.ROUNDED,
        border_style="bright_blue",
        padding=(1, 2),
    )
    console.print()
    console.print(panel)
    console.print(f"  🌐 [bold bright_cyan]Clickable Visualizer Link:[/bold bright_cyan] [bold underline bright_yellow][link={url}]{url}[/link][/bold underline bright_yellow]\n")

    if open_browser:
        webbrowser.open(url)

    console.print("  [dim]Press Ctrl+C to shut down and exit...[/dim]\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Shutting down visualizer...[/dim]")


def _print_findings_summary(correlated_assets: list) -> None:
    """Displays a stylized, color-coded summary table of correlated cryptographic assets."""
    table = Table(
        title="[bold bright_white]DISCOVERED CRYPTOGRAPHIC ASSETS (TOP 25 PREVIEW)[/bold bright_white]",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_cyan",
        expand=True,
    )
    table.add_column("Domain", style="cyan", width=14)
    table.add_column("Asset Name", style="bold white", width=28)
    table.add_column("Algorithm / Primitive", style="magenta", width=26)
    table.add_column("Location", style="dim white")
    table.add_column("Security", justify="center", width=12)

    domain_badges = {
        "source_code": "[bold cyan]● SOURCE[/bold cyan]",
        "artifacts": "[bold yellow]● ARTIFACT[/bold yellow]",
        "infrastructure": "[bold magenta]● INFRA[/bold magenta]",
        "network": "[bold blue]● NETWORK[/bold blue]",
    }

    for item in correlated_assets[:25]:
        asset = item.primary_asset
        domain_tag = domain_badges.get(asset.source_domain, f"[white]{asset.source_domain}[/white]")

        # Algorithm styling
        algo_str = f"{asset.algorithm}"
        if getattr(asset, "quantum_safe", False):
            algo_badge = f"[bold green]{algo_str}[/bold green]"
        elif getattr(asset, "shor_vulnerable", False):
            algo_badge = f"[bold red]{algo_str} ⚠[/bold red]"
        else:
            algo_badge = f"[bold yellow]{algo_str}[/bold yellow]"

        issues_count = len(asset.security_findings)
        if asset.raw_metadata.get("is_system_ca"):
            issues_str = "[dim cyan]✔ System CA[/dim cyan]"
        elif issues_count > 0:
            issues_str = f"[bold red]● {issues_count} Issue[/bold red]"
        else:
            issues_str = "[bold green]✔ Clean[/bold green]"

        table.add_row(
            domain_tag,
            asset.name[:26],
            f"{algo_badge} [dim]({asset.primitive[:10]})[/dim]",
            asset.location[-42:],
            issues_str,
        )

    console.print()
    console.print(table)
    if len(correlated_assets) > 25:
        console.print(f"  [dim cyan]ℹ Plus {len(correlated_assets) - 25:,} additional asset(s) fully cataloged in output CBOM.[/dim cyan]")


def _print_quantum_risk_summary(mosca_evals: dict) -> None:
    """Displays separate Mosca quantum risk assessment tables for Optimistic, Central, and Pessimistic scenarios."""
    scenarios_meta = [
        ("central", "2038 (Z = 12 yrs)", "bright_cyan"),
        ("pessimistic", "2033 (Z = 7 yrs)", "bright_red"),
        ("optimistic", "2045 (Z = 19 yrs)", "bright_green"),
    ]
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "QUANTUM_SAFE"]

    level_bars = {
        "CRITICAL": "[bold red]████████ CRITICAL[/bold red]",
        "HIGH": "[bold orange3]██████ HIGH[/bold orange3]",
        "MEDIUM": "[bold yellow]████ MEDIUM[/bold yellow]",
        "LOW": "[bold green]██ LOW[/bold green]",
        "QUANTUM_SAFE": "[bold bright_green]✔ QUANTUM-SAFE[/bold bright_green]",
    }

    for scenario, horizon_label, color in scenarios_meta:
        table = Table(
            title=f"[bold {color}]MOSCA QUANTUM RISK ASSESSMENT — {scenario.upper()} HORIZON [{horizon_label}][/bold {color}]",
            box=box.ROUNDED,
            border_style=color,
            header_style="bold bright_white",
            expand=True,
        )
        table.add_column("Risk Level", width=22)
        table.add_column("Asset Count", justify="center", width=14)
        table.add_column("SNDL Exposed", justify="center", width=14)
        table.add_column("NIST PQC Replacement Target", width=38)

        has_rows = False
        critical_count = 0

        for lvl in levels:
            matches = [
                m for m in mosca_evals.values()
                if getattr(m, "scenario_name", "central") == scenario and m.risk_level == lvl
            ]
            count = len(matches)
            if count == 0:
                continue

            has_rows = True
            sndl_count = sum(1 for m in matches if getattr(m, "sndl_vulnerable", False))
            if lvl in ["CRITICAL", "HIGH"]:
                critical_count += count

            sample_remediation = matches[0].recommended_pqc_replacement if matches else "None"

            table.add_row(
                level_bars.get(lvl, lvl),
                f"[bold white]{count:,}[/bold white]",
                f"[bold red]{sndl_count:,}[/bold red]" if sndl_count > 0 else "[green]0[/green]",
                f"[bright_white]{sample_remediation[:36]}[/bright_white]",
            )

        if has_rows:
            console.print()
            console.print(table)
            if critical_count > 0:
                console.print(f"  [bold red]⚠ CRITICAL ALERT:[/bold red] [red]{critical_count:,} asset(s) fail Mosca's inequality in the {scenario} scenario.[/red]")


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()