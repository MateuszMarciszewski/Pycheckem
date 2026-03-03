# pycheckem

Snapshot and diff Python runtime environments to debug "works on my machine" parity issues across dev, staging, prod, and containers.

**Zero external dependencies.** Everything uses the Python standard library.

## Install

```bash
pip install pycheckem
```

For color-coded terminal output (optional):

```bash
pip install pycheckem[pretty]
```

For TOML config support on Python < 3.11 (optional):

```bash
pip install pycheckem[toml]
```

For development:

```bash
git clone https://github.com/MateuszMarciszewski/Pycheckem.git
cd pycheckem
pip install -e ".[dev]"
```

## Quick Start

Capture a snapshot on each machine, then diff them:

```bash
# On staging
pycheckem snapshot -o staging.json --label staging

# On prod
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

What gets captured:

- **Python** — version, implementation, executable, prefix, platform
- **Packages** — all installed packages with versions, locations, dependencies, and install source (PyPI, editable, local, VCS, archive via PEP 610)
- **Environment variables** — filtered by default to exclude secrets
- **OS** — system, kernel, architecture, distro
- **Paths** — `sys.path` and `$PATH`
- **Config files** — SHA-256 hash and top-level key inventory
- **Project metadata** — name, version, dependencies from `pyproject.toml` / `setup.cfg`
- **Plugins** — data from any registered pycheckem collector plugins

### `pycheckem diff`

Compare two snapshot files.

```bash
pycheckem diff <snapshot_a> <snapshot_b> [options]
```

| Flag | Description |
|------|-------------|
| `--format` | Output format: `ascii` (default), `json`, `rich`, `side-by-side` / `sbs` |
| `--only` | Show only one section: `packages`, `env`, `python`, `os`, `paths`, `config`, `project` |
| `--exit-code` | Exit with code 1 if differences meet the severity threshold |
| `--fail-severity` | Minimum severity to trigger failure: `minor` (default), `major`, `critical` |
| `--ignore-packages` | Comma-separated packages to ignore (e.g. `pip,setuptools,wheel`) |
| `--ignore-env-vars` | Comma-separated env vars to ignore (e.g. `HOSTNAME,PWD`) |
| `--ignore-patterns` | Comma-separated regex patterns to ignore (e.g. `.*_CACHE.*`) |

### `pycheckem compare`

Snapshot the current environment and diff against a saved snapshot in one step:

```bash
pycheckem compare <saved_snapshot> [options]
```

Supports all `diff` flags plus snapshot options (`--label`, `--config-files`, `--include-sensitive`).

```bash
# Quick check: does my local env match prod?
pycheckem compare prod.json

# CI: fail if current env drifts from baseline
pycheckem compare baseline.json --exit-code --fail-severity major
```

### `pycheckem history`

Track environment snapshots over time:

```bash
# Add a snapshot to the history store
pycheckem history add snapshot.json

# List all snapshots in history
pycheckem history show

# Diff the last 2 snapshots in history
pycheckem history diff --last 2

# Diff with format and suppression options
pycheckem history diff --last 2 --format rich --ignore-packages pip,wheel
```

History is stored in `.pycheckem/history/` with timestamped filenames. Use `--dir` to set a custom base directory.

### `pycheckem remote`

Snapshot remote hosts via SSH and diff:

```bash
# Diff remote host against local environment
pycheckem remote user@prod-server

# Diff two remote hosts against each other
pycheckem remote user@staging user@prod

# With options
pycheckem remote user@host --timeout 60 --format rich --ignore-packages pip
```

Requires `pycheckem` to be installed on the remote host and `ssh` to be available locally.

### CI Gating

Use `--exit-code` and `--fail-severity` to gate CI pipelines:

```bash
# Fail on any difference
pycheckem diff staging.json prod.json --exit-code

# Fail only on major or critical (ignore minor additions)
pycheckem diff staging.json prod.json --exit-code --fail-severity major

# Fail only on critical (OS mismatch, major version changes)
pycheckem diff staging.json prod.json --exit-code --fail-severity critical
```

### Diff Suppression

Suppress noisy or expected differences via `pyproject.toml` or CLI flags:

```toml
# pyproject.toml
[tool.pycheckem]
ignore_packages = ["pip", "setuptools", "wheel"]
ignore_env_vars = ["HOSTNAME", "PWD", "SHLVL"]
ignore_patterns = [".*_CACHE.*"]
```

```bash
# Or inline via CLI flags
pycheckem diff a.json b.json --ignore-packages pip,setuptools --ignore-env-vars HOSTNAME
```

CLI flags merge with `pyproject.toml` config (they don't replace).

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| ASCII | `--format ascii` | Default terminal-friendly output |
| JSON | `--format json` | Machine-readable for scripts and CI |
| Rich | `--format rich` | Color-coded tables (requires `pip install pycheckem[pretty]`) |
| Side-by-side | `--format sbs` | Two-column comparison |

```bash
pycheckem diff staging.json prod.json --format json | jq '.summary'
```

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
print(result.summary.severity)        # "identical", "minor", "major", "critical"
print(result.summary.total_differences)
print(result.summary.breaking_changes) # list of human-readable strings

# Render
from pycheckem.render import ascii, json, rich, side_by_side
print(ascii(result))
print(json(result))
print(rich(result))           # color-coded output (falls back to ascii if rich not installed)
print(side_by_side(result))   # two-column comparison
```

### Snapshot Contents

The `Snapshot` object contains:

| Field | Type | Description |
|-------|------|-------------|
| `metadata` | `SnapshotMetadata` | Timestamp, hostname, label, pycheckem version |
| `python` | `PythonInfo` | Version, implementation, executable, prefix, platform |
| `packages` | `dict[str, PackageInfo]` | Installed packages with versions, dependencies, and install source |
| `env_vars` | `dict[str, str]` | Environment variables (sensitive filtered by default) |
| `os_info` | `OSInfo` | System, release, machine, distro |
| `paths` | `PathInfo` | `sys.path` and `$PATH` entries |
| `config_files` | `dict[str, ConfigFileInfo]` | Config file hashes and key inventories |
| `project` | `ProjectInfo` | Project name, version, dependencies from `pyproject.toml` / `setup.cfg` |
| `plugins` | `dict[str, dict]` | Data from registered collector plugins |

### Diff Severity Levels

| Severity | Triggers |
|----------|----------|
| `identical` | No differences |
| `minor` | Added packages, env var changes, path changes, config changes, project metadata changes, install source changes |
| `major` | Python minor version mismatch, package downgrades, removed packages, `requires-python` change |
| `critical` | Python major version change, OS/architecture mismatch, package major version change |

## Plugins

Extend pycheckem with custom collectors by registering entry points:

```toml
# In your plugin's pyproject.toml
[project.entry-points."pycheckem.collectors"]
my_collector = "my_package.collector:collect"
```

The collector function receives no arguments and returns a dict. Plugin data is stored in the snapshot under the `plugins` key.

## GitHub Actions

See [docs/github-actions.md](docs/github-actions.md) for a complete guide to CI integration, including:

- Baseline management with artifacts
- Severity threshold configuration
- Suppression rules in workflows
- PR comment integration
- History tracking in CI

## Requirements

- Python >= 3.8
- No external dependencies (core)
- Optional: `pip install pycheckem[pretty]` for color-coded output via `rich`
- Optional: `pip install pycheckem[toml]` for `pyproject.toml` config on Python < 3.11

## License

MIT
