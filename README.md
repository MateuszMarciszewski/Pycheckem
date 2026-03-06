[![PyPI version](https://img.shields.io/pypi/v/pycheckem)](https://pypi.org/project/pycheckem/)
[![Python versions](https://img.shields.io/pypi/pyversions/pycheckem)](https://pypi.org/project/pycheckem/)
[![License](https://img.shields.io/pypi/l/pycheckem)](LICENSE)
[![CI](https://github.com/MateuszMarciszewski/Pycheckem/actions/workflows/ci.yml/badge.svg)](https://github.com/MateuszMarciszewski/Pycheckem/actions)

# pycheckem

Your deployment failed because staging has `numpy 1.26.4` but production has `numpy 1.24.3`. You spent two hours figuring this out. pycheckem would have told you in one command.

pycheckem snapshots Python runtime environments — packages, versions, install sources, environment variables, OS details, paths, config files — and produces structured diffs that show you exactly what's different between any two environments. Use it to debug "works on my machine" issues, validate CI/CD environments, or catch drift before it causes production incidents.

**Zero external dependencies.** Everything uses the Python standard library.

## Quick Start

```bash
pip install pycheckem
```

Capture a snapshot on each machine, then diff them:

```bash
# On staging
pycheckem snapshot -o staging.json --label staging

# On production
pycheckem snapshot -o prod.json --label prod

# Compare
pycheckem diff staging.json prod.json
```

Output:

```
pycheckem: staging vs prod
═══════════════════════════════════════════════

Packages (3 differences)
  + gunicorn 21.2.0
  - debugpy 1.8.0
  ~ requests 2.31.0 → 2.28.0  ⚠ DOWNGRADE

Environment Variables (2 differences)
  + DATABASE_URL
  ~ LOG_LEVEL: DEBUG → WARNING

───────────────────────────────────────────────
Summary: 5 differences | Severity: MAJOR
Breaking: Package downgrade: requests 2.31.0 -> 2.28.0
```

Or compare your local environment against a saved snapshot in one step:

```bash
pycheckem compare prod.json
```

## Why Not Just `diff <(pip freeze)`?

| Capability | `pip freeze` diff | pycheckem |
|---|---|---|
| Package version mismatches | String diff only | Semantic version comparison with severity |
| Install source detection | No | Yes — PyPI, editable, local, VCS, archive (PEP 610) |
| Environment variables | Not captured | Captured and diffed (secrets filtered) |
| Python version, OS, architecture | Not captured | Captured and diffed |
| Config file changes | Not captured | SHA-256 hash + key inventory |
| Severity classification | No | Identical / minor / major / critical |
| CI gating | Manual scripting | Built-in `--exit-code --fail-severity` |
| Machine-readable output | No | JSON, side-by-side, rich (color-coded) |
| sys.path and PATH comparison | No | Yes |
| Native library detection | No | Yes — detects missing .so/.dylib deps (ldd/otool) |

## When to Use pycheckem

- **Debugging "works on my machine"** — compare your local environment against staging or prod to find the exact mismatch
- **CI environment validation** — diff CI against a baseline, fail the build if packages drifted
- **Pre-deployment checks** — compare the target environment against expectations before deploying
- **Migration validation** — after moving to a new server, container, or Python version, verify the environment matches
- **Audit trail** — snapshot environments over time and diff any two points in history
- **Docker multi-stage builds** — snapshot build and runtime stages to catch missing native libraries (.so files) before deployment
- **Remote debugging** — snapshot a remote host via SSH and diff against local

## What Gets Captured

Each snapshot records:

| Section | Details |
|---------|---------|
| **Python** | Version, implementation, executable, prefix, platform |
| **Packages** | All installed packages with versions, locations, dependencies, and install source (PEP 610) |
| **Environment Variables** | All env vars (sensitive values like passwords and keys are filtered by default) |
| **OS** | System, kernel, architecture, distro |
| **Paths** | `sys.path` and `$PATH` entries |
| **Config Files** | SHA-256 hash and top-level key inventory for any files you specify |
| **Project** | Name, version, dependencies from `pyproject.toml` / `setup.cfg` |
| **Native Libraries** | Shared library dependencies (.so/.pyd/.dylib) for compiled extensions — detects missing libs (uses `ldd`/`otool`) |
| **Plugins** | Data from any registered pycheckem collector plugins |

## CLI Reference

### `pycheckem snapshot`

Capture the current environment to a JSON file.

```bash
pycheckem snapshot -o <output_file> [options]
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output file path (use `-` for stdout) |
| `--label` | Label for this snapshot (e.g. "staging", "prod") |
| `--config-files` | Config files to hash (e.g. `.env`, `setup.cfg`) |
| `--include-sensitive` | Include sensitive env vars (passwords, tokens, keys) |

### `pycheckem diff`

Compare two snapshot files.

```bash
pycheckem diff <snapshot_a> <snapshot_b> [options]
```

| Flag | Description |
|------|-------------|
| `--format` | Output format: `ascii` (default), `json`, `rich`, `sbs` (side-by-side) |
| `--only` | Show only one section: `packages`, `env`, `python`, `os`, `paths`, `config`, `project` |
| `--exit-code` | Exit with code 1 if differences meet the severity threshold |
| `--fail-severity` | Minimum severity to trigger failure: `minor` (default), `major`, `critical` |
| `--ignore-packages` | Comma-separated packages to ignore (e.g. `pip,setuptools,wheel`) |
| `--ignore-env-vars` | Comma-separated env vars to ignore (e.g. `HOSTNAME,PWD`) |
| `--ignore-patterns` | Comma-separated regex patterns to ignore (e.g. `.*_CACHE.*`) |

### `pycheckem compare`

Snapshot the current environment and diff against a saved snapshot in one step.

```bash
pycheckem compare <saved_snapshot> [options]
```

Supports all `diff` flags plus snapshot options.

```bash
# Quick check: does my local env match prod?
pycheckem compare prod.json

# CI: fail if current env drifts from baseline
pycheckem compare baseline.json --exit-code --fail-severity major
```

### `pycheckem guard`

CI gate — snapshot the current environment and fail if it has drifted from a baseline. Like `compare`, but `--exit-code` is always on.

```bash
pycheckem guard baseline.json                          # fail on any drift
pycheckem guard baseline.json --fail-severity major    # fail only on major+
pycheckem guard baseline.json --format json            # machine-readable
pycheckem guard baseline.json --ignore-packages pip,setuptools
```

### `pycheckem verify`

Check installed packages against a requirements file or pyproject.toml. Reports missing, extra, and version-mismatched packages.

```bash
pycheckem verify requirements.txt                    # check deps
pycheckem verify pyproject.toml                      # works with pyproject.toml too
pycheckem verify requirements.txt --include-extras   # also show undeclared packages
pycheckem verify requirements.txt --exit-code        # fail if deps aren't satisfied
pycheckem verify requirements.txt --format json      # machine-readable
```

### `pycheckem history`

Track environment snapshots over time.

```bash
pycheckem history add snapshot.json          # Add to history
pycheckem history show                       # List all snapshots
pycheckem history diff --last 2              # Diff the last 2 snapshots
pycheckem history diff --last 2 --format rich  # With formatting options
```

History is stored in `.pycheckem/history/` with timestamped filenames.

### `pycheckem remote`

Snapshot remote hosts via SSH and diff.

```bash
pycheckem remote user@prod-server                # Diff remote vs local
pycheckem remote user@staging user@prod          # Diff two remotes
pycheckem remote user@host --timeout 60 --format rich
```

Requires `pycheckem` to be installed on the remote host and `ssh` available locally.

## CI Gating

Use `--exit-code` and `--fail-severity` to gate CI pipelines:

```bash
# Fail on any difference
pycheckem diff staging.json prod.json --exit-code

# Fail only on major or critical
pycheckem diff staging.json prod.json --exit-code --fail-severity major

# Fail only on critical (OS mismatch, major version changes)
pycheckem diff staging.json prod.json --exit-code --fail-severity critical
```

### Severity Levels

| Severity | Triggers |
|----------|----------|
| `identical` | No differences |
| `minor` | Added packages, env var changes, path changes, config changes, install source changes |
| `major` | Python minor version mismatch, package downgrades, removed packages |
| `critical` | Python major version change, OS/architecture mismatch, package major version change |

## Diff Suppression

Suppress noisy or expected differences via `pyproject.toml` or CLI flags:

```toml
# pyproject.toml
[tool.pycheckem]
ignore_packages = ["pip", "setuptools", "wheel"]
ignore_env_vars = ["HOSTNAME", "PWD", "SHLVL"]
ignore_patterns = [".*_CACHE.*"]
```

CLI flags merge with `pyproject.toml` config (they don't replace).

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| ASCII | `--format ascii` | Default terminal-friendly output |
| JSON | `--format json` | Machine-readable for scripts and CI |
| Rich | `--format rich` | Color-coded tables (requires `pip install pycheckem[pretty]`) |
| Side-by-side | `--format sbs` | Two-column comparison |

## Python API

```python
import pycheckem

# Capture a snapshot
snap = pycheckem.snapshot(label="dev")

# Save / load
pycheckem.save(snap, "dev.json")
loaded = pycheckem.load("dev.json")

# Diff two snapshots
snap_a = pycheckem.load("staging.json")
snap_b = pycheckem.load("prod.json")
result = pycheckem.diff(snap_a, snap_b)

# Inspect the result
print(result.summary.severity)          # "identical", "minor", "major", "critical"
print(result.summary.total_differences)
print(result.summary.breaking_changes)  # list of human-readable strings

# Render
from pycheckem.render import ascii, json, rich, side_by_side
print(ascii(result))
print(json(result))
```

## Plugins

Extend pycheckem with custom collectors by registering entry points:

```toml
# In your plugin's pyproject.toml
[project.entry-points."pycheckem.collectors"]
my_collector = "my_package.collector:collect"
```

The collector function receives no arguments and returns a dict. Plugin data is stored in the snapshot under the `plugins` key.

## GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for a complete CI integration guide with baseline management, suppression rules, and PR comment examples.

## pytest Integration

pycheckem includes a pytest plugin. Verify your environment as part of your test suite:

```bash
pytest --check-env requirements.txt
pytest --check-env pyproject.toml
```

Or configure it permanently in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
addopts = "--check-env=requirements.txt"
```

The environment check runs as the first test. If dependencies are missing or mismatched, you get a clear failure before any other tests run.

## Pre-commit Hook

Add pycheckem as a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MateuszMarciszewski/Pycheckem
    rev: v0.4.0
    hooks:
      - id: pycheckem-guard
        args: ["baseline.json"]
```

## MCP Server

For AI coding assistants (Claude Code, Cursor, Windsurf), install the MCP server:

```bash
pip install pycheckem-mcp
```

See [pycheckem-mcp/](pycheckem-mcp/) for configuration details.

## Installation Options

```bash
pip install pycheckem                  # Core (zero dependencies)
pip install pycheckem[pretty]          # Color-coded output via rich
pip install pycheckem[toml]            # pyproject.toml config on Python < 3.11
pip install -e ".[dev]"               # Development (editable + pytest)
```

**Requires:** Python >= 3.8

## License

[MIT](LICENSE)
