"""Command-line interface for agent-jail and aj."""

from __future__ import annotations

import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import NoReturn

from agent_jail import __version__
from agent_jail.config import init_config, load_config
from agent_jail.runners import get_runner


def print_help(prog: str) -> None:
    print(f"""agent-jail (v{__version__}) - Kernel-enforced sandboxing for AI agents

Usage:
  {prog} <command> [args...]     Run any agent harness, CLI tool, or script sandboxed
  {prog} claude / codex / pi     Run any coding agent CLI inside the sandbox
  {prog} python agent.py         Run custom Python agent loop (LangChain, DeepAgents, etc.)
  {prog} bash                    Launch an interactive sandboxed shell
  {prog}                         Launch an interactive sandboxed shell (default)

Options:
  --init                         Create default aj-conf.yaml in current project
  -h, --help                     Show this help message and exit
  -v, --version                  Show version number

Environment:
  AGENT_JAIL_CMD                 Override command string (executed via bash -c)
  HTTP_PROXY / HTTPS_PROXY       Automatically directed to local dynamic proxy
""")


def set_resource_limits() -> None:
    """Set process and file descriptor caps to prevent fork bombs and descriptor leaks."""
    try:
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (512, 512))
    except Exception:
        pass

    try:
        if hasattr(resource, "RLIMIT_NOFILE"):
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = min(2048, hard) if hard > 0 else 2048
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def start_proxy(allowlist: Path) -> tuple[subprocess.Popen, int]:
    """Start the unjailed dynamic forward proxy on 127.0.0.1:0 and read its assigned port."""
    proxy_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agent_jail.proxy",
            "--allowlist",
            str(allowlist),
            "--port",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if not proxy_proc.stdout:
        proxy_proc.kill()
        raise RuntimeError("Failed to open pipe for forward proxy process.")

    line = proxy_proc.stdout.readline().strip()
    if not line.startswith("PORT="):
        proxy_proc.kill()
        raise RuntimeError(f"Unexpected proxy initialization response: {line}")

    try:
        port = int(line[len("PORT=") :])
    except ValueError:
        proxy_proc.kill()
        raise RuntimeError(f"Invalid proxy port announced: {line}")

    return proxy_proc, port


def main() -> NoReturn:
    raw_args = sys.argv[1:]
    prog = Path(sys.argv[0]).name

    if raw_args and raw_args[0] in ("-h", "--help"):
        print_help(prog)
        sys.exit(0)

    if raw_args and raw_args[0] in ("-v", "--version"):
        print(f"agent-jail {__version__}")
        sys.exit(0)

    # 1. Project Directory Guard: Prevent running directly in $HOME or parent of it
    project = Path.cwd().resolve()
    home = Path.home().resolve()

    if project == home or project in home.parents:
        sys.stderr.write(
            f"agent-jail: refusing to run with project = $HOME or parent of it ({project})\n"
        )
        sys.exit(1)

    # Handle --init
    if raw_args and raw_args[0] == "--init":
        conf_file = init_config(project, home)
        sys.stderr.write(f"agent-jail: 📝 Initialized {conf_file.name} in {project}\n")
        sys.exit(0)

    # 2. Check platform prerequisites
    runner = get_runner()
    try:
        runner.check_prerequisites()
    except Exception as e:
        sys.stderr.write(f"agent-jail error: {e}\n")
        sys.exit(1)

    # 3. Load or initialize project configuration
    config, conf_path, was_created = load_config(project, home)
    if was_created:
        sys.stderr.write(f"agent-jail: 📝 Created default {conf_path.name} in project\n")

    # 4. Ephemeral Temp Directory
    run_tmp = Path(tempfile.mkdtemp(prefix="agent_jail_tmp_")).resolve()

    # Write domain allowlist to temp file for proxy
    allowlist_file = run_tmp / "allowed_domains.txt"
    allowlist_file.write_text("\n".join(config.allowed_domains) + "\n", encoding="utf-8")

    # 5. Start unjailed forward proxy
    try:
        proxy_proc, proxy_port = start_proxy(allowlist_file)
    except Exception as e:
        shutil.rmtree(run_tmp, ignore_errors=True)
        sys.stderr.write(f"agent-jail: failed to initialize proxy: {e}\n")
        sys.exit(1)

    # 6. Apply resource limits before executing child
    set_resource_limits()

    # 7. Determine command to execute
    if "AGENT_JAIL_CMD" in os.environ:
        cmd = ["/bin/bash", "-c", os.environ["AGENT_JAIL_CMD"]]
    elif raw_args:
        cmd = raw_args
    else:
        # Default to interactive shell
        cmd = [os.environ.get("SHELL", "/bin/bash")]

    sys.stderr.write(
        f"agent-jail: 🔒 {project} | 🌐 proxy:127.0.0.1:{proxy_port} ({conf_path.name})\n"
    )
    sys.stderr.flush()

    # 8. Build command & environment
    exec_cmd = runner.build_command(
        project=project,
        home=home,
        proxy_port=proxy_port,
        run_tmp=run_tmp,
        cmd=cmd,
        config=config,
    )
    safe_env = runner.build_safe_env(proxy_port, run_tmp, config=config)

    exit_code = 0
    try:
        # Launch child process with scrubbed environment
        child = subprocess.Popen(exec_cmd, env=safe_env)

        # Forward signals to child process
        def handle_signal(sig: int, frame: object) -> None:
            try:
                child.send_signal(sig)
            except Exception:
                pass

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        exit_code = child.wait()
    except KeyboardInterrupt:
        exit_code = 130
    except Exception as e:
        sys.stderr.write(f"agent-jail execution error: {e}\n")
        exit_code = 1
    finally:
        # Cleanup proxy and ephemeral directory
        try:
            proxy_proc.terminate()
            proxy_proc.wait(timeout=2.0)
        except Exception:
            proxy_proc.kill()

        shutil.rmtree(run_tmp, ignore_errors=True)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
