"""System environment, sandbox, Ollama, and storage diagnostic suite."""

from __future__ import annotations
import sys
import os
import platform
import shutil
import importlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from imgint.core.ai.ollama import OllamaClient
from imgint.core.sandbox.process import SandboxRunner


class DiagnosticRunner:
    """Runs automated health checks across all system layers and operational prerequisites."""

    @classmethod
    def run_all_checks(cls, console: Optional[Console] = None) -> Dict[str, Any]:
        console = console or Console()
        results: Dict[str, Any] = {
            "all_passed": True,
            "checks": [],
        }

        # 1. Python Environment
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        py_ok = sys.version_info >= (3, 10)
        arch = platform.machine()
        os_info = f"{platform.system()} {platform.release()}"
        results["checks"].append({
            "category": "Runtime",
            "name": "Python Environment",
            "status": py_ok,
            "details": f"Python {py_ver} ({platform.architecture()[0]}, {arch}) on {os_info}",
            "hint": "Python 3.10+ required" if not py_ok else None,
        })
        if not py_ok:
            results["all_passed"] = False

        # 2. Forensic Dependencies
        required_libs = [
            ("PIL", "Pillow (Image Processing)"),
            ("numpy", "NumPy (Matrix Math)"),
            ("cryptography", "Cryptography (HMAC & Signatures)"),
            ("imagehash", "ImageHash (Perceptual pHash)"),
            ("click", "Click (CLI Framework)"),
            ("rich", "Rich (Terminal UI)"),
        ]
        missing_libs = []
        for mod, name in required_libs:
            try:
                importlib.import_module(mod)
            except ImportError:
                missing_libs.append(name)

        deps_ok = len(missing_libs) == 0
        results["checks"].append({
            "category": "Dependencies",
            "name": "Core Forensic Libraries",
            "status": deps_ok,
            "details": "All 6 core forensic packages active" if deps_ok else f"Missing: {', '.join(missing_libs)}",
            "hint": "Run: pip install -r requirements.txt" if not deps_ok else None,
        })
        if not deps_ok:
            results["all_passed"] = False

        # 3. Sandboxed Worker Isolation Test
        try:
            # Create a 1x1 test image
            from PIL import Image
            import io
            import base64
            test_buf = io.BytesIO()
            Image.new("RGB", (8, 8), color="blue").save(test_buf, "PNG")
            raw_bytes_b64 = base64.b64encode(test_buf.getvalue()).decode("ascii")

            worker_res = SandboxRunner.run_decode_tasks(None, raw_bytes=raw_bytes_b64, tasks=["dimensions"])
            sandbox_ok = worker_res.get("success", False) and "dimensions" in worker_res.get("tasks", {})
            details_str = "Process-isolated worker operational (ADR-004 compliant)" if sandbox_ok else worker_res.get("error", "Failed")
        except Exception as e:
            sandbox_ok = False
            details_str = f"Sandbox spawn failed: {e}"

        results["checks"].append({
            "category": "Sandbox",
            "name": "Subprocess Isolation Worker",
            "status": sandbox_ok,
            "details": details_str,
            "hint": "Check subprocess permissions" if not sandbox_ok else None,
        })
        if not sandbox_ok:
            results["all_passed"] = False

        # 4. Local Ollama AI Vision Service
        ollama = OllamaClient()
        ollama_online = ollama.is_available()
        if ollama_online:
            v_models = ollama.list_vision_models()
            all_m = ollama.list_models()
            if v_models:
                ollama_details = f"Online at {ollama.host} ({len(v_models)} vision model(s): {', '.join(v_models)})"
            elif all_m:
                ollama_details = f"Online at {ollama.host} ({len(all_m)} text models installed, no vision models)"
            else:
                ollama_details = f"Online at {ollama.host} (0 models installed)"
        else:
            ollama_details = "Daemon offline at http://localhost:11434"

        results["checks"].append({
            "category": "Local AI",
            "name": "Ollama Vision Daemon",
            "status": ollama_online,
            "details": ollama_details,
            "hint": "Run 'ollama serve' and 'ollama pull llama3.2-vision' to enable AI interrogation" if not ollama_online else None,
            "optional": True,
        })

        # 5. Evidence Vault Storage & Permissions
        vault_path = Path("./evidence_store").resolve()
        try:
            vault_path.mkdir(parents=True, exist_ok=True)
            test_file = vault_path / ".doctor_perm_test"
            test_file.write_text("test")
            test_file.unlink()
            total, used, free = shutil.disk_usage(str(vault_path))
            free_gb = free / (1024 ** 3)
            storage_ok = free_gb >= 0.5  # At least 500MB free
            storage_details = f"Writable at {vault_path} ({free_gb:.1f} GB free space)"
        except Exception as e:
            storage_ok = False
            storage_details = f"Vault write error: {e}"

        results["checks"].append({
            "category": "Storage",
            "name": "Evidence Vault Permissions",
            "status": storage_ok,
            "details": storage_details,
            "hint": "Ensure write permissions for evidence storage" if not storage_ok else None,
        })
        if not storage_ok:
            results["all_passed"] = False

        # 6. Man Page & CLI Access
        man_path = Path("/usr/local/share/man/man1/matazero.1")
        has_man = man_path.exists() or Path("docs/man/matazero.1").exists()
        results["checks"].append({
            "category": "Documentation",
            "name": "UNIX Manual Page (matazero.1)",
            "status": has_man,
            "details": "Installed in system manpath" if man_path.exists() else "Available in docs/man/matazero.1",
            "hint": "Run ./install.sh to install global man page" if not man_path.exists() else None,
            "optional": True,
        })

        # Render Rich UI Output
        cls._render_ui(results, console)
        return results

    @classmethod
    def _render_ui(cls, results: Dict[str, Any], console: Console) -> None:
        table = Table(title="matazero System Health & Diagnostics", border_style="cyan", header_style="bold cyan")
        table.add_column("Category", style="dim", width=14)
        table.add_column("Diagnostic Check", style="bold white", width=28)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Details & Guidance", style="white")

        for c in results["checks"]:
            if c["status"]:
                badge = "[bold green][✔] PASS[/bold green]"
            elif c.get("optional"):
                badge = "[bold yellow][!] INFO[/bold yellow]"
            else:
                badge = "[bold red][X] FAIL[/bold red]"

            details_text = c["details"]
            if c.get("hint") and not c["status"]:
                details_text += f"\n[yellow]↳ Tip: {c['hint']}[/yellow]"

            table.add_row(c["category"], c["name"], badge, details_text)

        console.print(table)

        all_passed = results["all_passed"]
        if all_passed:
            console.print(
                Panel(
                    "[bold green][✔] System is fully healthy and ready for forensic investigations.[/bold green]\n"
                    "[dim]All core engines, sandboxed workers, and evidence vaults are operating nominally.[/dim]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold red][X] System health checks detected critical issues.[/bold red]\n"
                    "[yellow]Please review the diagnostic table above to resolve required dependencies.[/yellow]",
                    border_style="red",
                )
            )
