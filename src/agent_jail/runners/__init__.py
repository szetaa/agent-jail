"""Platform-specific sandboxing runners."""

import sys
from agent_jail.runners.base import BaseRunner
from agent_jail.runners.macos import MacOSRunner
from agent_jail.runners.linux import LinuxRunner


def get_runner() -> BaseRunner:
    """Return the appropriate sandbox runner for the current operating system."""
    if sys.platform == "darwin":
        return MacOSRunner()
    elif sys.platform.startswith("linux"):
        return LinuxRunner()
    else:
        raise NotImplementedError(
            f"agent-jail is currently supported on macOS and Linux (got: {sys.platform})"
        )


__all__ = ["BaseRunner", "MacOSRunner", "LinuxRunner", "get_runner"]
