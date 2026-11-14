"""Linux Bubblewrap (bwrap) sandbox runner."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import TYPE_CHECKING

from agent_jail.runners.base import BaseRunner

if TYPE_CHECKING:
    from agent_jail.config import JailConfig


class LinuxRunner(BaseRunner):
    """Executes processes confined by Bubblewrap (bwrap) mount & user namespaces."""

    def check_prerequisites(self) -> None:
        if not shutil.which("bwrap"):
            raise RuntimeError(
                "agent-jail requires Bubblewrap ('bwrap') on Linux.\n"
                "Please install it using:\n"
                "  sudo apt-get install bubblewrap   # Debian / Ubuntu\n"
                "  sudo dnf install bubblewrap       # Fedora / RHEL\n"
                "  sudo pacman -S bubblewrap         # Arch Linux"
            )

    def build_command(
        self,
        project: Path,
        home: Path,
        proxy_port: int,
        run_tmp: Path,
        cmd: list[str],
        config: JailConfig,
    ) -> list[str]:
        proxy_url = f"http://127.0.0.1:{proxy_port}"

        bwrap_args: list[str] = [
            "bwrap",
            # Security hygiene: Kill child orphans when parent exits
            "--die-with-parent",
            # Scrub environment variables inside container
            "--clearenv",
            "--setenv", "PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "--setenv", "HOME", str(home),
            "--setenv", "USER", os.environ.get("USER", "user"),
            "--setenv", "LOGNAME", os.environ.get("LOGNAME", os.environ.get("USER", "user")),
            "--setenv", "SHELL", os.environ.get("SHELL", "/bin/bash"),
            "--setenv", "TERM", os.environ.get("TERM", "xterm-256color"),
            "--setenv", "LANG", os.environ.get("LANG", "en_US.UTF-8"),
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "HTTP_PROXY", proxy_url,
            "--setenv", "HTTPS_PROXY", proxy_url,
            "--setenv", "ALL_PROXY", proxy_url,
            "--setenv", "NO_PROXY", "localhost,127.0.0.1",
            "--setenv", "http_proxy", proxy_url,
            "--setenv", "https_proxy", proxy_url,
            "--setenv", "all_proxy", proxy_url,
            "--setenv", "no_proxy", "localhost,127.0.0.1",
        ]

        if "VIRTUAL_ENV" in os.environ:
            bwrap_args.extend(["--setenv", "VIRTUAL_ENV", os.environ["VIRTUAL_ENV"]])

        # User passthrough env vars
        if config and config.env_passthrough:
            for var in config.env_passthrough:
                if var in os.environ:
                    bwrap_args.extend(["--setenv", var, os.environ[var]])

        # Resolve configured read, hide, and write paths relative to project
        resolved_reads = [
            project
            if str(r) in (".", "./")
            else (project / r)
            if not r.is_absolute()
            else r
            for r in (config.fs_read if config else [])
        ]
        resolved_writes = [
            project
            if str(w) in (".", "./")
            else (project / w)
            if not w.is_absolute()
            else w
            for w in (config.fs_write if config else [])
        ]
        resolved_hides = [
            project
            if str(h) in (".", "./")
            else (project / h)
            if not h.is_absolute()
            else h
            for h in (config.fs_hide if config else [])
        ]

        # Root and standard mounts
        bwrap_args.extend([
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--tmpfs", "/run",
            # Mask user HOME directory with an empty tmpfs
            "--tmpfs", str(home),
        ])

        # Bind project directory:
        # 1. If project itself is in resolved_writes, mount read-write (--bind).
        # 2. Elif project is in resolved_reads, mount read-only (--ro-bind).
        # 3. Otherwise, mask project with an empty tmpfs (--tmpfs project), allowing only explicitly configured subpaths.
        if project in resolved_writes:
            bwrap_args.extend(["--bind", str(project), str(project)])
        elif project in resolved_reads:
            bwrap_args.extend(["--ro-bind", str(project), str(project)])
        else:
            bwrap_args.extend(["--tmpfs", str(project)])

        # Mount permitted subpaths and additional read paths
        for r_path in resolved_reads:
            if r_path != project and r_path.exists():
                bwrap_args.extend(["--ro-bind", str(r_path), str(r_path)])

        # Mount permitted subpaths and additional write paths
        for w_path in resolved_writes:
            if w_path != project and w_path.exists():
                bwrap_args.extend(["--bind", str(w_path), str(w_path)])

        # Protect persistence vectors in $PROJECT
        for trap in [
            ".git/hooks",
            ".git/config",
            ".envrc",
            ".mcp.json",
            ".vscode",
            "aj-conf.yaml",
            "aj-conf.yml",
            "aj-conf.toml",
            ".allowed_domains",
            ".allowed_domains.txt",
        ]:
            trap_path = project / trap
            if trap_path.exists():
                bwrap_args.extend(["--ro-bind", str(trap_path), str(trap_path)])

        # Hide user-specified secret files or directories (masking them)
        if resolved_hides:
            for h_path in resolved_hides:
                if h_path.exists():
                    if h_path.is_dir():
                        bwrap_args.extend(["--tmpfs", str(h_path)])
                    else:
                        bwrap_args.extend(["--ro-bind", "/dev/null", str(h_path)])

        # Mount ~/.pi if present, protecting code and config
        pi_home = home / ".pi"
        if pi_home.is_dir():
            bwrap_args.extend(["--bind", str(pi_home), str(pi_home)])
            pi_agent = pi_home / "agent"
            for sub in ["extensions", "bin", "skills"]:
                sub_path = pi_agent / sub
                if sub_path.is_dir():
                    bwrap_args.extend(["--ro-bind", str(sub_path), str(sub_path)])
            for cfg in ["settings.json", "models.json", "auth.json"]:
                cfg_path = pi_agent / cfg
                if cfg_path.is_file():
                    bwrap_args.extend(["--ro-bind", str(cfg_path), str(cfg_path)])

        # Mount user tools and language runtimes read-only if present
        for local_dir in [
            home / ".local",
            home / ".cache",
            home / ".pyenv",
            home / ".nvm",
            home / ".fnm",
            home / ".volta",
            home / ".bun",
            home / ".cargo",
            home / ".rustup",
        ]:
            if local_dir.is_dir():
                bwrap_args.extend(["--ro-bind", str(local_dir), str(local_dir)])

        # Remount $HOME as read-only after all submounts are created
        bwrap_args.extend(["--remount-ro", str(home)])

        # Namespaces & directory
        bwrap_args.extend([
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--share-net",
            "--chdir", str(project),
        ])

        bwrap_args.extend(cmd)
        return bwrap_args
