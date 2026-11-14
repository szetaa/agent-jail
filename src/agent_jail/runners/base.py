"""Base abstract runner interface for sandbox execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_jail.config import JailConfig


class BaseRunner(ABC):
    """Abstract interface defining platform sandboxing behavior."""

    @abstractmethod
    def check_prerequisites(self) -> None:
        """Validate required OS binaries (e.g., sandbox-exec or bwrap)."""
        pass

    @abstractmethod
    def build_command(
        self,
        project: Path,
        home: Path,
        proxy_port: int,
        run_tmp: Path,
        cmd: list[str],
        config: JailConfig,
    ) -> list[str]:
        """Construct the sandbox launcher command and arguments."""
        pass

    def build_safe_env(
        self, proxy_port: int, run_tmp: Path, config: JailConfig | None = None
    ) -> dict[str, str]:
        """Return a scrubbed environment dictionary stripping host secrets and credentials."""
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "HOME": str(Path.home().resolve()),
            "USER": os.environ.get("USER", "user"),
            "LOGNAME": os.environ.get("LOGNAME", os.environ.get("USER", "user")),
            "SHELL": os.environ.get("SHELL", "/bin/bash"),
            "TERM": os.environ.get("TERM", "xterm-256color"),
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
            "TMPDIR": str(run_tmp),
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1",
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "all_proxy": proxy_url,
            "no_proxy": "localhost,127.0.0.1",
        }
        if "VIRTUAL_ENV" in os.environ:
            safe_env["VIRTUAL_ENV"] = os.environ["VIRTUAL_ENV"]

        # User-configured passthrough environment variables
        if config and config.env_passthrough:
            for var in config.env_passthrough:
                if var in os.environ:
                    safe_env[var] = os.environ[var]

        return safe_env
