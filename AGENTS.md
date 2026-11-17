# AGENTS.md — Developer & Agent Guide for `agent-jail`

**`agent-jail`** (PyPI: `agent-jail-cli`, CLI: `aj` / `agent-jail`) provides zero-overhead, OS-level sandboxing for autonomous AI agents using **Apple Seatbelt** (`sandbox-exec`) on macOS and **Bubblewrap** (`bwrap`) on Linux, paired with a local egress-filtering HTTP proxy.

---

## Architecture & Key Files

- `src/agent_jail/cli.py` — CLI entrypoint, dynamic proxy startup, resource limits, signal forwarding.
- `src/agent_jail/config.py` — Loads `aj-conf.yaml`, resolves `read` / `write` / `hide` paths, `allowed_domains`, and `env.passthrough`.
- `src/agent_jail/proxy.py` — Local forward proxy (`127.0.0.1:0`) enforcing the domain allowlist and blocking SSRF.
- `src/agent_jail/runners/base.py` — Base runner interface & environment variable scrubbing.
- `src/agent_jail/runners/macos.py` & `src/agent_jail/resources/agent-jail.sb` — macOS Seatbelt profile and command builder.
- `src/agent_jail/runners/linux.py` — Linux Bubblewrap command builder.

---

## Security & Platform Invariants

1. **Keep macOS and Linux parity:** Any new persistence trap or read-only protection added to `src/agent_jail/resources/agent-jail.sb` must also be added to `src/agent_jail/runners/linux.py` (and vice versa).
2. **Canonicalize paths:** Always `.resolve()` filesystem paths before passing them to Seatbelt or `bwrap` (prevents symlink escapes and `/tmp` → `/private/tmp` mismatches on macOS).
3. **macOS `RLIMIT_NPROC`:** Do **not** set `RLIMIT_NPROC` on `darwin` — macOS enforces it per-UID across the entire user session, which triggers `Errno 35 (EAGAIN)` when the user has many background processes.
4. **Keep `agent-jail.sb` packaged:** Verify `agent_jail/resources/agent-jail.sb` is included in built wheels (`unzip -l dist/*.whl | grep agent-jail.sb`).

---

## Local Development & Testing

```bash
# Run unit tests
uv run pytest

# Reinstall locally (use --reinstall --no-cache when version hasn't changed, or --editable)
uv tool install --reinstall --no-cache .
# or:
uv tool install --editable --force .
```

---

## Release Process (GitHub + PyPI)

PyPI publishing is automated via `.github/workflows/publish.yml` using **OIDC Trusted Publishing** to `agent-jail-cli` whenever a `v*` tag is pushed.

1. Bump the version in **both** places:
   - `pyproject.toml` (`version = "X.Y.Z"`)
   - `src/agent_jail/__init__.py` (`__version__ = "X.Y.Z"`)
2. Commit and push to `main`:
   ```bash
   git add pyproject.toml src/agent_jail/__init__.py
   git commit -m "chore: bump version to X.Y.Z"
   git push
   ```
3. Tag and push to trigger the PyPI release workflow:
   ```bash
   git tag vX.Y.Z
   git push --tags
   ```
4. *(Manual fallback only, if needed)*:
   ```bash
   rm -rf dist/ && uv build
   set -a && source .env && set +a
   uv publish
   ```
