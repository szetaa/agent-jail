"""Configuration management for agent-jail using aj-conf.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import shutil
import sys
from typing import Any
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


DEFAULT_CONFIG_TEMPLATE = """# aj-conf.yaml - Configuration for agent-jail (aj)

network:
  # Outbound domains, wildcards (*.domain.com), or specific host:port endpoints
  allowed_domains:
    - github.com
    - "*.github.com"
    - githubusercontent.com
    - "*.githubusercontent.com"
    - pypi.org
    - "*.pypi.org"
    - pythonhosted.org
    - "*.pythonhosted.org"
    - huggingface.co
    - "*.huggingface.co"
    - registry.npmjs.org
    # Cloud LLM APIs (uncomment as needed):
    # - api.openai.com
    # - api.anthropic.com
    # - generativelanguage.googleapis.com
    # - openrouter.ai
    # Local LLM servers (standard ports):
    # - 127.0.0.1:11434  # Ollama
    # - 127.0.0.1:8080   # llama.cpp (llama-server)
    # - 127.0.0.1:4000   # LiteLLM Proxy
    # - 127.0.0.1:1234   # LM Studio
    # - 127.0.0.1:8000   # vLLM / Local FastAPI

filesystem:
  # Directories permitted for read access.
  # Default: ["."] grants read access to the entire project directory.
  # Restrict to specific subfolders (e.g. ["src", ".venv"]) for granular reads.
  read:
    - .

  # Specific files or directories to hide completely (deny read).
  # Useful when read: ["."] is enabled but you want to protect secrets.
  hide:
    # - .env
    # - secrets

  # Directories permitted for write access.
  # Default: ["."] grants write access to the project directory.
  # Restrict to specific subfolders (e.g. ["output", ".cache"]) for granular access,
  # or leave empty ([]) to make the entire project strictly read-only.
  write:
    - .

env:
  # Host environment variables to pass into the sandbox
  passthrough:
    # - OPENAI_API_KEY
    # - ANTHROPIC_API_KEY
    # - GEMINI_API_KEY
"""


@dataclass
class JailConfig:
    """Parsed agent-jail project configuration."""

    allowed_domains: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    fs_read: list[Path] = field(default_factory=list)
    fs_hide: list[Path] = field(default_factory=list)
    fs_write: list[Path] = field(default_factory=list)
    env_passthrough: list[str] = field(default_factory=list)


def init_config(project: Path, home: Path | None = None) -> Path:
    """Create aj-conf.yaml in the project directory.

    If ~/.aj/default_conf.yaml exists, copies it; otherwise writes the default template.
    """
    conf_path = project / "aj-conf.yaml"
    if conf_path.exists():
        return conf_path

    if home is None:
        home = Path.home().resolve()

    # Check for user template in ~/.aj/default_conf.yaml or .yml
    user_defaults = [
        home / ".aj" / "default_conf.yaml",
        home / ".aj" / "default_conf.yml",
    ]
    for user_def in user_defaults:
        if user_def.is_file():
            shutil.copyfile(user_def, conf_path)
            return conf_path

    # Fallback to default template
    conf_path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    return conf_path


def resolve_fs_path(entry: str | Path, project: Path | None = None) -> Path:
    """Resolve a filesystem path entry, supporting relative paths and $PROJECT."""
    p_str = str(entry).strip()
    if project is not None:
        p_str = p_str.replace("${PROJECT}", str(project)).replace("$PROJECT", str(project))
    path = Path(p_str).expanduser()
    if not path.is_absolute():
        if project is not None:
            if p_str in (".", "./"):
                return project.resolve()
            return (project / path).resolve()
        return path.resolve()
    return path.resolve()


def load_config(project: Path, home: Path) -> tuple[JailConfig, Path, bool]:
    """Load project configuration. Returns (JailConfig, path, was_created).

    Checks for:
    1. aj-conf.yaml
    2. aj-conf.yml
    3. aj-conf.toml (fallback)
    4. Legacy .allowed_domains
    5. Auto-creates aj-conf.yaml (copying ~/.aj/default_conf.yaml if present)
    """
    for yaml_name in ["aj-conf.yaml", "aj-conf.yml"]:
        yaml_path = project / yaml_name
        if yaml_path.is_file():
            raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            return _build_config(raw, project=project), yaml_path, False

    toml_path = project / "aj-conf.toml"
    if toml_path.is_file() and tomllib is not None:
        raw = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        return _build_config(raw, project=project), toml_path, False

    # Check for legacy .allowed_domains
    for legacy_name in [".allowed_domains", ".allowed_domains.txt"]:
        legacy_path = project / legacy_name
        if legacy_path.is_file():
            domains = []
            for line in legacy_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
            return (
                _build_config({"network": {"allowed_domains": domains}}, project=project),
                legacy_path,
                False,
            )

    # Auto-initialize aj-conf.yaml in project
    created_path = init_config(project, home)
    raw = yaml.safe_load(created_path.read_text(encoding="utf-8")) or {}
    return _build_config(raw, project=project), created_path, True


def _build_config(raw: dict[str, Any], project: Path | None = None) -> JailConfig:
    network = raw.get("network") or {}
    filesystem = raw.get("filesystem") or {}
    env_cfg = raw.get("env") or {}

    # Extract allowed domains
    domains_raw = network.get("allowed_domains") or []
    domains = [str(d).strip() for d in domains_raw if str(d).strip()]

    # Automatically derive localhost ports if specified in allowed_domains (e.g. 127.0.0.1:11434 or localhost:8080)
    ports: list[int] = []
    for entry in domains:
        if ":" in entry:
            host_part, port_str = entry.split(":", 1)
            host_clean = host_part.lower().strip()
            if host_clean in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
                try:
                    ports.append(int(port_str.strip()))
                except ValueError:
                    pass

    # Support explicit allowed_ports if also provided
    ports_raw = network.get("allowed_ports") or []
    for p in ports_raw:
        try:
            p_int = int(p)
            if p_int not in ports:
                ports.append(p_int)
        except (ValueError, TypeError):
            pass

    # Read paths:
    # If "read" is explicitly present in filesystem: parse the list (even if empty [])
    # If "read" is not present (e.g. legacy configs): default to [project]
    if "read" in filesystem:
        read_raw = filesystem.get("read") or []
        read_paths = [
            resolve_fs_path(p, project)
            for p in read_raw
            if str(p).strip()
        ]
    else:
        read_paths = [project] if project is not None else []

    # Hide paths: specific files or directories to deny read access to
    hide_raw = filesystem.get("hide") or []
    hide_paths = [
        resolve_fs_path(p, project)
        for p in hide_raw
        if str(p).strip()
    ]

    # Write paths
    write_raw = filesystem.get("write") or []
    write_paths = [
        resolve_fs_path(p, project)
        for p in write_raw
        if str(p).strip()
    ]

    # Env passthrough
    pass_raw = env_cfg.get("passthrough") or []
    passthrough = [
        str(e).strip() for e in pass_raw if str(e).strip()
    ]

    return JailConfig(
        allowed_domains=domains,
        allowed_ports=ports,
        fs_read=read_paths,
        fs_hide=hide_paths,
        fs_write=write_paths,
        env_passthrough=passthrough,
    )
