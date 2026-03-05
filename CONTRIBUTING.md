# Contributing to pycheckem

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/MateuszMarciszewski/Pycheckem.git
cd pycheckem
python -m venv .venv
.venv/Scripts/activate   # Windows/Git Bash
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR. The CI runs tests across Python 3.8-3.13 on Linux, macOS, and Windows.

## Code Style

- Zero external dependencies for core functionality (everything in `pycheckem/` uses stdlib only)
- `from __future__ import annotations` in every module
- Use `typing` module types (`Dict`, `List`, `Optional`) for Python 3.8 compatibility
- Run `ruff check .` and `ruff format .` before committing

## Project Structure

```
pycheckem/
  collectors/    # One module per data source (python, packages, env_vars, etc.)
  render/        # Output formatters (ascii, json, rich, side_by_side)
  types.py       # All dataclasses (Snapshot types + Diff types)
  snapshot.py    # Snapshot orchestration, save/load
  diff.py        # Diff engine, severity scoring
  cli.py         # argparse CLI
  config.py      # pyproject.toml config loading
  suppression.py # Post-diff filtering
  history.py     # Snapshot history store
  remote.py      # SSH remote snapshots
  plugins.py     # Entry-point plugin discovery
tests/
  test_*.py      # One test file per module
```

## Adding a New Collector

1. Create `pycheckem/collectors/my_collector.py` with a `collect_*()` function
2. Add the corresponding dataclass to `pycheckem/types.py`
3. Wire it into `pycheckem/snapshot.py`
4. Add diff logic in `pycheckem/diff.py`
5. Update renderers in `pycheckem/render/`
6. Add tests in `tests/test_my_collector.py`

## Submitting Changes

1. Fork the repo and create a branch
2. Make your changes with tests
3. Run the full test suite
4. Open a PR with a description of what and why

## Reporting Issues

Open an issue at https://github.com/MateuszMarciszewski/Pycheckem/issues with:
- What you expected to happen
- What actually happened
- Python version and OS
- Steps to reproduce
