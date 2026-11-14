"""Tests for macOS Seatbelt and Linux Bubblewrap runners."""

import os
from pathlib import Path
import tempfile

from agent_jail.config import JailConfig
from agent_jail.runners.macos import MacOSRunner
from agent_jail.runners.linux import LinuxRunner


def test_safe_env_scrubbing_and_passthrough():
    runner = MacOSRunner()
    # Inject sensitive env var into os.environ
    os.environ["SECRET_API_KEY"] = "sk-super-secret"
    os.environ["SSH_AUTH_SOCK"] = "/tmp/ssh.sock"
    os.environ["ALLOWED_PASSTHROUGH_TOKEN"] = "allowed-secret-123"

    config = JailConfig(env_passthrough=["ALLOWED_PASSTHROUGH_TOKEN"])
    safe_env = runner.build_safe_env(proxy_port=12345, run_tmp=Path("/tmp/test_tmp"), config=config)

    assert "SECRET_API_KEY" not in safe_env
    assert "SSH_AUTH_SOCK" not in safe_env
    assert safe_env["ALLOWED_PASSTHROUGH_TOKEN"] == "allowed-secret-123"
    assert safe_env["HTTP_PROXY"] == "http://127.0.0.1:12345"
    assert safe_env["HTTPS_PROXY"] == "http://127.0.0.1:12345"
    assert safe_env["NO_PROXY"] == "localhost,127.0.0.1"
    assert safe_env["TMPDIR"] == "/tmp/test_tmp"


def test_macos_runner_build_command():
    runner = MacOSRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "my_project"
        home = tmp_path / "home"
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        config = JailConfig(
            allowed_ports=[8000, 9000],
            fs_read=[Path("/tmp/extra_read")],
            fs_write=[Path("/tmp/extra_write")],
        )

        cmd = runner.build_command(
            project=project,
            home=home,
            proxy_port=9999,
            run_tmp=run_tmp,
            cmd=["python", "agent.py"],
            config=config,
        )

        assert cmd[0] == "sandbox-exec"
        assert cmd[1] == "-f"
        profile_file = run_tmp / "agent-jail.sb"
        assert str(profile_file) == cmd[2]
        assert f"HOME={home}" in cmd
        assert f"PROJECT={project}" in cmd
        assert "PROXY_PORT=9999" in cmd
        assert f"RUN_TMP={run_tmp}" in cmd
        assert cmd[-2:] == ["python", "agent.py"]

        # Verify dynamic rules were injected into Seatbelt profile
        profile_content = profile_file.read_text()
        assert '(allow network-outbound (to tcp "localhost:8000"))' in profile_content
        assert '(allow network-outbound (to tcp "localhost:9000"))' in profile_content
        assert '(allow file-read-data (subpath "/tmp/extra_read"))' in profile_content
        assert '(allow file-write* (subpath "/tmp/extra_write"))' in profile_content


def test_linux_runner_build_command():
    runner = LinuxRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "my_project"
        project.mkdir()
        home = tmp_path / "home"
        home.mkdir()
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        # Create persistence traps inside project
        git_hooks = project / ".git" / "hooks"
        git_hooks.mkdir(parents=True)
        envrc = project / ".envrc"
        envrc.touch()

        extra_read = tmp_path / "read_target"
        extra_read.mkdir()
        extra_write = tmp_path / "write_target"
        extra_write.mkdir()

        config = JailConfig(
            fs_read=[extra_read],
            fs_write=[extra_write],
            env_passthrough=["TEST_VAR"],
        )
        os.environ["TEST_VAR"] = "test_val"

        cmd = runner.build_command(
            project=project,
            home=home,
            proxy_port=8888,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config,
        )

        assert cmd[0] == "bwrap"
        assert "--die-with-parent" in cmd
        assert "--clearenv" in cmd
        assert "--tmpfs" in cmd
        assert str(home) in cmd
        assert "--remount-ro" in cmd

        # Verify traps are protected read-only
        assert "--ro-bind" in cmd
        assert str(git_hooks) in cmd
        assert str(envrc) in cmd

        # Verify custom mounts
        assert str(extra_read) in cmd
        assert str(extra_write) in cmd
        assert "--setenv" in cmd
        assert "TEST_VAR" in cmd

        assert cmd[-1] == "bash"


def test_macos_runner_scoped_writes():
    runner = MacOSRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "scoped_proj"
        project.mkdir()
        home = tmp_path / "home"
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        # Case 1: write: [] (strictly read-only project)
        config_ro = JailConfig(fs_write=[])
        runner.build_command(
            project=project,
            home=home,
            proxy_port=9999,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_ro,
        )
        profile_ro = (run_tmp / "agent-jail.sb").read_text()
        assert f'(allow file-write* (subpath "{project}"))' not in profile_ro
        base_write_block = profile_ro.split(";; 1. UNIVERSAL WRITE POLICY")[1].split(";; Explicit write denials")[0]
        assert '(subpath (param "PROJECT"))' not in base_write_block
        # Ephemeral run_tmp is still writable
        assert '(subpath (param "RUN_TMP"))' in profile_ro

    # Case 2: write: ["output"] (scoped write access)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "scoped_proj"
        project.mkdir()
        home = tmp_path / "home"
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        config_scoped = JailConfig(fs_write=[Path("output")])
        runner.build_command(
            project=project,
            home=home,
            proxy_port=9999,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_scoped,
        )
        profile_scoped = (run_tmp / "agent-jail.sb").read_text()
        output_path = project / "output"
        assert f'(allow file-write* (subpath "{output_path}"))' in profile_scoped
        assert f'(allow file-read-data (subpath "{output_path}"))' in profile_scoped
        assert f'(allow file-write* (subpath "{project}"))' not in profile_scoped

        # Verify anti-tampering deny rules appear AFTER dynamic write rules
        write_idx = profile_scoped.index(f'(allow file-write* (subpath "{output_path}"))')
        deny_idx = profile_scoped.index('(subpath  (string-append (param "PROJECT") "/.git/hooks"))')
        assert write_idx < deny_idx

        # Config anti-tampering is present in deny block
        assert '(literal  (string-append (param "PROJECT") "/aj-conf.yaml"))' in profile_scoped


def test_linux_runner_scoped_writes():
    runner = LinuxRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "linux_proj"
        project.mkdir()
        output_dir = project / "output"
        output_dir.mkdir()
        home = tmp_path / "home"
        home.mkdir()
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        # Case 1: read-only project (fs_write is empty, fs_read has project)
        config_ro = JailConfig(fs_read=[project], fs_write=[])
        cmd_ro = runner.build_command(
            project=project,
            home=home,
            proxy_port=8888,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_ro,
        )
        # Should be mounted with --ro-bind, NOT --bind
        project_ro_idx = cmd_ro.index(str(project))
        assert cmd_ro[project_ro_idx - 1] == "--ro-bind"

        # Case 2: granular scoped write (fs_write=[output_dir], fs_read=[project])
        config_scoped = JailConfig(fs_read=[project], fs_write=[output_dir])
        cmd_scoped = runner.build_command(
            project=project,
            home=home,
            proxy_port=8888,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_scoped,
        )
        # Project is --ro-bind
        proj_idx = cmd_scoped.index(str(project))
        assert cmd_scoped[proj_idx - 1] == "--ro-bind"
        # output_dir is --bind
        output_idx = cmd_scoped.index(str(output_dir))
        assert cmd_scoped[output_idx - 1] == "--bind"

        # Case 3: full project write (fs_write=[project])
        config_full = JailConfig(fs_write=[project])
        cmd_full = runner.build_command(
            project=project,
            home=home,
            proxy_port=8888,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_full,
        )
        proj_full_idx = cmd_full.index(str(project))
        assert cmd_full[proj_full_idx - 1] == "--bind"


def test_macos_runner_scoped_reads_and_hides():
    runner = MacOSRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "read_hide_proj"
        project.mkdir()
        env_file = project / ".env"
        env_file.touch()
        src_dir = project / "src"
        src_dir.mkdir()
        home = tmp_path / "home"
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        # Case 1: read project, hide .env
        config_hide = JailConfig(
            fs_read=[project],
            fs_hide=[env_file],
            fs_write=[],
        )
        runner.build_command(
            project=project,
            home=home,
            proxy_port=9999,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_hide,
        )
        profile = (run_tmp / "agent-jail.sb").read_text()
        assert f'(allow file-read-data (subpath "{project}"))' in profile
        assert f'(deny file-read-data (literal "{env_file}"))' in profile
        # Verify deny rule comes after allow rule
        read_idx = profile.index(f'(allow file-read-data (subpath "{project}"))')
        hide_idx = profile.index(f'(deny file-read-data (literal "{env_file}"))')
        assert read_idx < hide_idx

    # Case 2: scoped read (only src/ is readable, project root is not)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "read_hide_proj"
        project.mkdir()
        src_dir = project / "src"
        src_dir.mkdir()
        home = tmp_path / "home"
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        config_scoped_read = JailConfig(
            fs_read=[src_dir],
            fs_write=[],
        )
        runner.build_command(
            project=project,
            home=home,
            proxy_port=9999,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_scoped_read,
        )
        profile = (run_tmp / "agent-jail.sb").read_text()
        assert f'(allow file-read-data (subpath "{src_dir}"))' in profile
        assert f'(allow file-read-data (subpath "{project}"))' not in profile


def test_linux_runner_scoped_reads_and_hides():
    runner = LinuxRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "linux_read_hide_proj"
        project.mkdir()
        env_file = project / ".env"
        env_file.touch()
        src_dir = project / "src"
        src_dir.mkdir()
        home = tmp_path / "home"
        home.mkdir()
        run_tmp = tmp_path / "run_tmp"
        run_tmp.mkdir()

        # Case 1: read project, hide .env
        config_hide = JailConfig(
            fs_read=[project],
            fs_hide=[env_file],
            fs_write=[],
        )
        cmd_hide = runner.build_command(
            project=project,
            home=home,
            proxy_port=8888,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_hide,
        )
        # Project is --ro-bind
        proj_idx = cmd_hide.index(str(project))
        assert cmd_hide[proj_idx - 1] == "--ro-bind"
        # .env is masked with --ro-bind /dev/null
        assert str(env_file) in cmd_hide
        env_idx = cmd_hide.index(str(env_file))
        assert cmd_hide[env_idx - 1] == "/dev/null"
        assert cmd_hide[env_idx - 2] == "--ro-bind"

        # Case 2: scoped read (only src/ is readable, project root is masked with tmpfs)
        config_scoped_read = JailConfig(
            fs_read=[src_dir],
            fs_write=[],
        )
        cmd_scoped = runner.build_command(
            project=project,
            home=home,
            proxy_port=8888,
            run_tmp=run_tmp,
            cmd=["bash"],
            config=config_scoped_read,
        )
        # Project is masked with --tmpfs
        proj_idx2 = cmd_scoped.index(str(project))
        assert cmd_scoped[proj_idx2 - 1] == "--tmpfs"
        # src_dir is --ro-bind
        src_idx = cmd_scoped.index(str(src_dir))
        assert cmd_scoped[src_idx - 1] == "--ro-bind"
