"""macOS Seatbelt (sandbox-exec) sandbox runner."""

from __future__ import annotations

import importlib.resources
from pathlib import Path
import shutil
from typing import TYPE_CHECKING

from agent_jail.runners.base import BaseRunner

if TYPE_CHECKING:
    from agent_jail.config import JailConfig


def _escape_sbpl(path: Path | str) -> str:
    """Escape backslashes and double quotes for safe interpolation into SBPL rules."""
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


class MacOSRunner(BaseRunner):
    """Executes processes confined by macOS Seatbelt (sandbox-exec)."""

    def check_prerequisites(self) -> None:
        if not shutil.which("sandbox-exec"):
            raise RuntimeError(
                "agent-jail requires 'sandbox-exec' on macOS, but it was not found in PATH."
            )

    def get_profile_path(
        self,
        run_tmp: Path,
        config: JailConfig | None = None,
        project: Path | None = None,
    ) -> Path:
        """Extract and provide the Seatbelt profile file, appending dynamic config rules."""
        target_path = run_tmp / "agent-jail.sb"
        if not target_path.exists():
            resource = (
                importlib.resources.files("agent_jail.resources")
                .joinpath("agent-jail.sb")
                .read_text(encoding="utf-8")
            )

            # 1. Dynamic write rules (injected before anti-tampering deny rules)
            write_rules: list[str] = []
            if config and config.fs_write:
                write_rules.append("\n;; User-configured write paths")
                for w_path in config.fs_write:
                    resolved_w = (
                        project
                        if str(w_path) in (".", "./") and project
                        else (project / w_path)
                        if project and not w_path.is_absolute()
                        else w_path
                    )
                    escaped_w = _escape_sbpl(resolved_w)
                    write_rules.append(f'(allow file-write* (subpath "{escaped_w}"))')
                    write_rules.append(f'(allow file-read-data (subpath "{escaped_w}"))')

            dynamic_write_block = "\n".join(write_rules)
            if ";; __DYNAMIC_WRITE_RULES__" in resource:
                content = resource.replace(";; __DYNAMIC_WRITE_RULES__", dynamic_write_block)
            else:
                content = resource + "\n" + dynamic_write_block

            # 2. Dynamic read paths
            read_rules: list[str] = []
            if config and config.fs_read:
                read_rules.append("\n;; User-configured read paths")
                for r_path in config.fs_read:
                    resolved_r = (
                        project
                        if str(r_path) in (".", "./") and project
                        else (project / r_path)
                        if project and not r_path.is_absolute()
                        else r_path
                    )
                    escaped_r = _escape_sbpl(resolved_r)
                    read_rules.append(f'(allow file-read-data (subpath "{escaped_r}"))')

            dynamic_read_block = "\n".join(read_rules)
            if ";; __DYNAMIC_READ_RULES__" in content:
                content = content.replace(";; __DYNAMIC_READ_RULES__", dynamic_read_block)
            else:
                content = content + "\n" + dynamic_read_block

            # 3. Dynamic hide paths (deny read access to sensitive files/folders)
            hide_rules: list[str] = []
            if config and config.fs_hide:
                hide_rules.append("\n;; User-configured hidden paths (deny read)")
                for h_path in config.fs_hide:
                    resolved_h = (
                        project
                        if str(h_path) in (".", "./") and project
                        else (project / h_path)
                        if project and not h_path.is_absolute()
                        else h_path
                    )
                    escaped_h = _escape_sbpl(resolved_h)
                    hide_rules.append(f'(deny file-read-data (literal "{escaped_h}"))')
                    hide_rules.append(f'(deny file-read-data (subpath "{escaped_h}"))')
                    hide_rules.append(f'(deny file-read-metadata (literal "{escaped_h}"))')
                    hide_rules.append(f'(deny file-read-metadata (subpath "{escaped_h}"))')

            dynamic_hide_block = "\n".join(hide_rules)
            if ";; __DYNAMIC_HIDE_RULES__" in content:
                content = content.replace(";; __DYNAMIC_HIDE_RULES__", dynamic_hide_block)
            else:
                content = content + "\n" + dynamic_hide_block

            # 4. Dynamic network ports
            extra_rules: list[str] = []
            if config:
                if config.allowed_ports:
                    extra_rules.append("\n;; User-configured localhost ports")
                    for port in config.allowed_ports:
                        extra_rules.append(f'(allow network-outbound (to tcp "localhost:{port}"))')

            if extra_rules:
                content = content + "\n" + "\n".join(extra_rules) + "\n"

            target_path.write_text(content, encoding="utf-8")
        return target_path

    def build_command(
        self,
        project: Path,
        home: Path,
        proxy_port: int,
        run_tmp: Path,
        cmd: list[str],
        config: JailConfig,
    ) -> list[str]:
        profile_path = self.get_profile_path(run_tmp, config, project=project)

        return [
            "sandbox-exec",
            "-f",
            str(profile_path),
            "-D",
            f"HOME={home}",
            "-D",
            f"PROJECT={project}",
            "-D",
            f"PROXY_PORT={proxy_port}",
            "-D",
            f"RUN_TMP={run_tmp}",
            *cmd,
        ]
