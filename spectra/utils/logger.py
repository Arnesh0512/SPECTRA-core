"""
spectra.utils.logger
=========================
Centralized terminal logging, banners, and status output using Rich.
"""

import logging
import sys
from typing import Optional

# Ensure UTF-8 console output encoding on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text

# Shared rich console instance
console = Console(legacy_windows=False)

BANNER = r"""
======================================================================
   _____ _____  ______ _____ _______ _____            
  / ____|  __ \|  ____/ ____|__   __|  __ \     /\    
 | (___ | |__) | |__  | |      | |  | |__) |   /  \   
  \___ \|  ___/|  __| | |      | |  |  _  /   / /\ \  
  ____) | |    | |____| |____  | |  | | \ \  / ____ \ 
 |_____/|_|    |______\_____|  |_|  |_|  \_\/_/    \_\
 
 Enterprise Multi-Domain Cryptographic Inventory & CBOM Engine
======================================================================
"""

def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configures the standard Python logging system with RichHandler."""
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                show_path=False,
                markup=True
            )
        ]
    )

    # Suppress verbose HTTP wire traffic from cloud SDKs while retaining authentication info
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
    logging.getLogger("azure.core").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("azure.identity").setLevel(logging.INFO)

    return logging.getLogger("spectra")


logger = setup_logger()


def print_banner(version: str = "1.0.0") -> None:
    """Renders the CLI startup banner with quantum styling."""
    title = Text("spectra", style="bold cyan")
    subtitle = Text(f"Enterprise Cryptographic Discovery & PQC Risk Engine (v{version})", style="italic white")
    panel_content = Text.assemble(title, "\n", subtitle)

    console.print(
        Panel(
            panel_content,
            border_style="bright_blue",
            expand=False,
            padding=(1, 4)
        )
    )


def log_step(step_name: str) -> None:
    """Prints a highlighted step indicator or prominent domain separator."""
    import re
    from rich import box
    from rich.panel import Panel

    m = re.match(r"^Domain\s+(\d/\d)[:\s]+(.*)$", step_name, re.IGNORECASE)
    if m:
        dom_idx = m.group(1)
        dom_title = m.group(2).upper().strip()
        domain_styles = {
            "1/4": ("bold bright_cyan", "cyan", "⚛"),
            "2/4": ("bold bright_magenta", "magenta", "☁"),
            "3/4": ("bold bright_yellow", "yellow", "🌐"),
            "4/4": ("bold bright_green", "green", "🛡️"),
        }
        title_style, border_style, icon = domain_styles.get(dom_idx, ("bold bright_white", "cyan", "⚡"))

        console.print("\n\n\n\n", end="")
        console.print(
            Panel(
                f"[{title_style}]{icon}  DOMAIN {dom_idx}: {dom_title}[/{title_style}]",
                border_style=border_style,
                box=box.HEAVY,
                expand=True,
                padding=(0, 2),
            )
        )
    else:
        console.print(f"\n\n[bold green]➜[/bold green] [bold white]{step_name}[/bold white]")


def log_info(message: str) -> None:
    """Prints an informational message."""
    console.print(f"  [cyan]ℹ[/cyan] {message}")


def log_success(message: str) -> None:
    """Prints a success message."""
    console.print(f"  [bold green]✔[/bold green] {message}")


def log_warning(message: str) -> None:
    """Prints a warning message."""
    console.print(f"  [bold yellow]⚠[/bold yellow] {message}")


def log_error(message: str) -> None:
    """Prints an error message."""
    console.print(f"  [bold red]✖[/bold red] {message}")


def log_header(title: str) -> None:
    """Prints a distinct header section banner."""
    console.print(f"\n[bold bright_cyan]{'=' * 60}[/bold bright_cyan]")
    console.print(f"[bold bright_white]  {title.upper()}[/bold bright_white]")
    console.print(f"[bold bright_cyan]{'=' * 60}[/bold bright_cyan]")