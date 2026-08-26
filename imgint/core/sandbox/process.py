"""Sandbox runner executing child decode processes with resource caps per ADR-004."""

from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


class SandboxExecutionError(Exception):
    """Raised when sandbox child process crashes or times out."""
    pass


class SandboxRunner:
    """Spawns an isolated child process to execute decode-requiring analysers."""

    DEFAULT_TIMEOUT_SECONDS = 6.0

    @classmethod
    def run_decode_tasks(
        cls,
        file_path: str | Path,
        tasks: Optional[List[str]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Dict[str, Any]:
        req_tasks = tasks or ["dimensions", "phashes", "dominant_colors", "entropy"]
        payload = {
            "file_path": str(Path(file_path).resolve()),
            "tasks": req_tasks,
        }
        input_json = json.dumps(payload)

        # Ensure child process can always locate imgint package
        repo_root = str(Path(__file__).parent.parent.parent.parent.resolve())
        env = dict(sys.modules.get("os", {}).environ if hasattr(sys, "modules") else {})
        import os
        env = os.environ.copy()
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{repo_root}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else repo_root

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=repo_root,
            )
            stdout_str, stderr_str = proc.communicate(input=input_json, timeout=timeout)
            if proc.returncode != 0:
                return {
                    "success": False,
                    "error": f"Child exited with code {proc.returncode}: {stderr_str.strip()}",
                }

            result = json.loads(stdout_str.strip())
            return result
        except subprocess.TimeoutExpired:
            proc.kill()
            return {"success": False, "error": f"Child decode timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": f"Sandbox execution exception: {e}"}
