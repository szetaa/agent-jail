"""Tests for CLI parameter resolution, YAML config management, and project guard."""

from pathlib import Path
import tempfile

from agent_jail.config import init_config, load_config


def test_config_auto_init_and_load_yaml():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "project"
        project.mkdir()
        home = tmp_path / "home"
        home.mkdir()

        # Initial load when empty should auto-create aj-conf.yaml
        config, conf_path, was_created = load_config(project, home)
        assert was_created is True
        assert conf_path == project / "aj-conf.yaml"
        assert "github.com" in config.allowed_domains
        assert conf_path.exists()

        # Second load: already exists, was_created is False
        config2, conf_path2, was_created2 = load_config(project, home)
        assert was_created2 is False
        assert conf_path2 == conf_path


def test_config_copies_user_default_template():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "project"
        project.mkdir()
        home = tmp_path / "home"
        home.mkdir()

        # Create ~/.aj/default_conf.yaml
        aj_dir = home / ".aj"
        aj_dir.mkdir()
        user_template = aj_dir / "default_conf.yaml"
        user_template.write_text("""# Custom user template
network:
  allowed_domains:
    - my-company.internal
    - 127.0.0.1:11434
""", encoding="utf-8")

        config, conf_path, was_created = load_config(project, home)
        assert was_created is True
        assert conf_path == project / "aj-conf.yaml"
        assert conf_path.read_text(encoding="utf-8") == user_template.read_text(encoding="utf-8")
        assert "my-company.internal" in config.allowed_domains
        assert 11434 in config.allowed_ports  # Derived from 127.0.0.1:11434


def test_config_custom_values_yaml():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = tmp_path / "project"
        project.mkdir()
        home = tmp_path / "home"
        home.mkdir()

        conf_file = project / "aj-conf.yaml"
        conf_file.write_text("""
network:
  allowed_domains:
    - custom.api.com
    - "*.custom.api.com"
    - 127.0.0.1:11434
    - localhost:8080

filesystem:
  read:
    - /tmp/shared_models
  write:
    - /tmp/output_data

env:
  passthrough:
    - CUSTOM_API_KEY
    - DEBUG_FLAG
""", encoding="utf-8")

        config, conf_path, was_created = load_config(project, home)
        assert was_created is False
        assert "custom.api.com" in config.allowed_domains
        # Auto-derived localhost ports from allowed_domains
        assert 11434 in config.allowed_ports
        assert 8080 in config.allowed_ports
        assert Path("/tmp/shared_models").resolve() in config.fs_read
        assert Path("/tmp/output_data").resolve() in config.fs_write
        assert config.env_passthrough == ["CUSTOM_API_KEY", "DEBUG_FLAG"]


def test_home_guard_logic():
    home = Path("/Users/alice")

    # Same as home
    project_same = Path("/Users/alice")
    assert project_same == home or project_same in home.parents

    # Parent of home
    project_parent = Path("/Users")
    assert project_parent == home or project_parent in home.parents

    # Root
    project_root = Path("/")
    assert project_root == home or project_root in home.parents

    # Valid subproject inside home
    valid_subproject = Path("/Users/alice/projects/cool-agent")
    assert not (valid_subproject == home or valid_subproject in home.parents)


def test_config_relative_write_paths():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = (tmp_path / "my_project").resolve()
        project.mkdir()
        home = (tmp_path / "home").resolve()
        home.mkdir()

        conf_file = project / "aj-conf.yaml"
        conf_file.write_text("""
filesystem:
  write:
    - .
    - artifacts
    - "$PROJECT/output"
    - /tmp/absolute_path
""", encoding="utf-8")

        config, _, _ = load_config(project, home)
        assert project in config.fs_write
        assert (project / "artifacts") in config.fs_write
        assert (project / "output") in config.fs_write
        assert Path("/tmp/absolute_path").resolve() in config.fs_write


def test_config_read_and_hide_paths():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        project = (tmp_path / "my_project").resolve()
        project.mkdir()
        home = (tmp_path / "home").resolve()
        home.mkdir()

        conf_file = project / "aj-conf.yaml"
        conf_file.write_text("""
filesystem:
  read:
    - src
    - .venv
  hide:
    - .env
    - secrets/
  write:
    - output
""", encoding="utf-8")

        config, _, _ = load_config(project, home)
        assert (project / "src") in config.fs_read
        assert (project / ".venv") in config.fs_read
        assert project not in config.fs_read
        assert (project / ".env") in config.fs_hide
        assert (project / "secrets") in config.fs_hide
        assert (project / "output") in config.fs_write
