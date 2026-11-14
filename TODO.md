# Pre-Publish Review & Release Checklist (`agent-jail`)

## 1. Completed in This Pass ✅

- [x] **Generalized Default Configuration (`aj-conf.yaml`, `config.py`, `README.md`):**
  - Replaced bespoke ports (`8050`, `8054`, `8020`) with standard local LLM endpoints out of the box (commented examples ready to uncomment):
    - `127.0.0.1:11434` (Ollama)
    - `127.0.0.1:8080` (llama.cpp `llama-server`)
    - `127.0.0.1:4000` (LiteLLM Proxy)
    - `127.0.0.1:1234` (LM Studio)
    - `127.0.0.1:8000` (vLLM / Local FastAPI)
  - Added commented examples for major Cloud LLM APIs (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `openrouter.ai`) and enabled `registry.npmjs.org` by default alongside PyPI, GitHub, and HuggingFace.
  - Replaced bespoke folder examples (`dossiers`) with generic names (`output`, `.cache`).
- [x] **Removed Personal Paths & Legacy Artifacts:**
  - Replaced `/Users/ralph` in `tests/test_cli.py` with `/Users/alice`.
  - Removed legacy `PI_JAIL_CMD` environment variable fallback in `src/agent_jail/cli.py`.
  - Removed obsolete `FEATURE_SCOPED_PROJECT_WRITES.md` and unused `src/agent_jail/resources/allowed_domains.default`.
  - Cleaned local `dist/` build artifacts.
- [x] **Hardened Security & Cross-Tool Compatibility:**
  - **Proxy Loopback Equivalence (`proxy.py`):** Allowlisting `127.0.0.1:<port>` or `localhost:<port>` now seamlessly allows both `localhost` and `127.0.0.1`/`::1` on that port without triggering false-positive SSRF blocks on DNS resolution.
  - **Seatbelt Profile Escaping (`macos.py`):** Escaped `\` and `"` in dynamic filesystem paths before interpolating into SBPL rules to prevent syntax breakage or rule injection from unusual path names.
  - **Persistence Trap Hardening (`agent-jail.sb` & `linux.py`):** Added `.mcp.json` to read-only anti-tampering locks alongside `.git/hooks`, `.git/config`, `.envrc`, `.vscode`, and `aj-conf.yaml`.
  - **Out-of-the-Box Toolchain Support (`agent-jail.sb` & `linux.py`):** Added read-only access for standard user runtime managers (`~/.pyenv`, `~/.nvm`, `~/.fnm`, `~/.volta`, `~/.bun`, `~/.cargo`, `~/.rustup`) alongside `~/.local` and `~/.cache` so Node/TS, Python, and Rust-based agent CLIs (`claude`, `codex`, `gemini`, `pi`, `aider`) work out of the box.

---

## 2. Final Checks for You Before Making the Repo Public

- [ ] **Check Author Identity in `pyproject.toml`, `LICENSE`, and Git Config:**
  - `pyproject.toml` and `LICENSE` list `Ralph` (no last name or email).
  - Your git commits currently use `ralph <szetaa@gmail.com>`. If you want to hide your personal Gmail in the public commit history, set your GitHub noreply email before running the squash step below:
    ```bash
    git config user.name "szetaa"
    git config user.email "szetaa@users.noreply.github.com"
    ```
- [ ] **Decide Whether `aj-conf.yaml` in Repo Root Should Be Tracked or Ignored:**
  - Currently `aj-conf.yaml` is tracked in the root of `agent-jail` (serving both as an example and as the config when dogfooding `aj` inside this repo). Keep it tracked if you want visitors to see it in the repo root, or `git rm --cached aj-conf.yaml` and add `aj-conf.yaml` to `.gitignore` if you prefer `aj --init` to generate it cleanly.

---

## 3. Step-by-Step Release Procedure (Clean Squashed History on `main`)

Because earlier commits (`00840f2..868308e`) contain intermediate work, bespoke port numbers (`8050`/`8054`), `/Users/ralph`, and design notes, **merging normally (`git merge ongoing`) would leave all of that visible in `git log`**.

Instead, use an **orphan branch squash** to publish a single, pristine initial commit on `main` and delete the `ongoing` branch from the public remote:

```bash
# 1. Verify tests pass
uv run --with pytest pytest -v

# 2. (Optional) Set public git author identity if you don't want your personal email in git log
git config user.name "Ralph"
git config user.email "szetaa@users.noreply.github.com"

# 3. Stage all current clean files on ongoing
git add -A
git commit -m "chore: pre-release cleanup and standard defaults"

# 4. Create a fresh, history-free branch from the current tree
git checkout --orphan clean-main
git add -A
git commit -m "feat: initial public release of agent-jail (v0.1.5)"

# 5. Replace main with this single clean commit and force-push to origin
git branch -M clean-main main
git push -f origin main

# 6. Delete the intermediate 'ongoing' branch locally and on GitHub so old commits aren't exposed
git push origin --delete ongoing
git branch -D ongoing

# 7. Tag the release
git tag v0.1.5
git push origin v0.1.5
```

> **Note:** After deleting `ongoing` and force-pushing `main`, flip the repository visibility to **Public** in GitHub Settings -> Danger Zone -> Change repository visibility.

---

## 4. Future Roadmap Ideas (Post-Release `v0.2+`)

- [ ] **Kernel-Enforced Network Isolation on Linux (`--unshare-net` + UNIX Socket Bridge):**
  - On macOS, Seatbelt blocks raw sockets at the kernel level (`(deny network-outbound)`). On Linux, `bwrap` currently uses `--share-net` so the sandbox can reach `127.0.0.1:<proxy_port>`, meaning raw non-HTTP sockets can bypass env-var proxy settings. Bridging `bwrap --unshare-net` to the host proxy via a mounted UNIX domain socket would give Linux the exact same kernel-level network enforcement as macOS.
- [ ] **Protect Non-Existent Persistence Traps on Linux:**
  - On macOS, Seatbelt blocks writing to `.envrc`, `.mcp.json`, and `.vscode` even if those files don't exist yet when `aj` starts. On Linux, `bwrap --ro-bind` only mounts paths that already exist at startup. Creating empty read-only placeholders or mounting `/dev/null` for missing trap files when `$PROJECT` is writable would close that gap on Linux.
- [ ] **Harness State Directories (`~/.claude`, `~/.codex`, `~/.gemini`):**
  - Currently `~/.pi` has first-class read/write state with read-only config protection (`settings.json`, `auth.json`, `skills`, `extensions`). Adding similar read-only config guards for `~/.claude` (`settings.json`, `CLAUDE.md`) and `~/.codex` will make `aj claude` and `aj codex` work seamlessly while preventing self-modification.
