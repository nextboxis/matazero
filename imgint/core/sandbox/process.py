"""Sandbox runner executing child decode processes with resource caps per ADR-004."""

from __future__ import annotations
import json
import os
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
    _SENSITIVE_ENV_TOKENS = (
        "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH",
        "PROXY", "COOKIE", "SESSION", "PRIVATE",
    )

    @classmethod
    def _build_sanitized_env(cls, repo_root: str) -> Dict[str, str]:
        """Constructs a minimal, credential-scrubbed environment for the child worker per ADR-004."""
        env: Dict[str, str] = {}
        for k, v in os.environ.items():
            k_upper = k.upper()
            if any(tok in k_upper for tok in cls._SENSITIVE_ENV_TOKENS):
                continue
            env[k] = v

        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{repo_root}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else repo_root
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONNOUSERSITE"] = "1"
        env["NO_PROXY"] = "*"
        return env

    @classmethod
    def run_decode_tasks(
        cls,
        file_path: Optional[str | Path] = None,
        tasks: Optional[List[str]] = None,
        extra_params: Optional[Dict[str, Any]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        req_tasks = tasks or ["dimensions", "phashes", "dominant_colors", "entropy"]
        payload: Dict[str, Any] = {
            "tasks": req_tasks,
        }
        if file_path:
            payload["file_path"] = str(Path(file_path).resolve())
        if extra_params:
            payload.update(extra_params)
        if kwargs:
            payload.update(kwargs)
        input_json = json.dumps(payload)

        repo_root = str(Path(__file__).parent.parent.parent.parent.resolve())
        env = cls._build_sanitized_env(repo_root)

        cmd = [sys.executable, "-m", "imgint.core.sandbox.worker"]

        proc: Optional[subprocess.Popen] = None
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
            if proc:
                try:
                    proc.kill()
                    proc.communicate()
                except Exception:
                    pass
            return {"success": False, "error": f"Child decode timed out after {timeout}s"}
        except Exception as e:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.communicate()
                except Exception:
                    pass
            return {"success": False, "error": f"Sandbox execution exception: {e}"}
