# Changelog

All notable changes to pycheckem will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-03-05

### Added
- `pycheckem guard` subcommand — CI gate with automatic exit-code behavior
- `pycheckem verify` subcommand — check installed packages against requirements.txt or pyproject.toml
- Requirements.txt parser (handles pinned versions, ranges, extras, markers, comments)
- pyproject.toml dependency parser (PEP 621 `[project.dependencies]`)
- Version specifier matching (==, !=, >=, <=, >, <, ~=, wildcards)
- pytest plugin — `pytest --check-env requirements.txt` to verify env before tests
- MCP server (`pycheckem-mcp`) for AI coding assistants (Claude Code, Cursor, Windsurf)
- GitHub Action (`pycheckem-guard`) for CI marketplace
- Pre-commit hook support (`.pre-commit-hooks.yaml`)
- `llms.txt` for LLM-friendly documentation
- Claude Code and Cursor integration files
- LICENSE file (MIT)
- CHANGELOG.md
- CONTRIBUTING.md
- GitHub Actions CI (test matrix: 3 OSes x Python 3.8-3.13 + ruff lint)

### Changed
- README rewritten with problem-first opening, comparison table, badges
- PyPI metadata expanded with keywords, classifiers, project URLs
- Public API docstrings overhauled with Args/Returns/Examples
- pyproject.toml registers pytest plugin entry point

## [0.3.1] - 2026-03-03

### Added
- PEP 610 install source detection — packages now report how they were installed (PyPI, editable, local, VCS, archive)
- `SourceChange` dataclass and `source_changed` field on `PackageDiff`
- Install source diffing across all renderers (ascii, rich, side-by-side)
- Suppression module handles source-only changes

### Changed
- Updated PyPI project description

## [0.3.0] - 2026-03-02

### Added
- Diff suppression rules via `pyproject.toml` config and CLI flags (`--ignore-packages`, `--ignore-env-vars`, `--ignore-patterns`)
- Project awareness collector — reads `pyproject.toml` / `setup.cfg` for project name, version, dependencies
- Side-by-side diff renderer (`--format sbs`)
- GitHub Actions integration example workflow
- Remote snapshot via SSH (`pycheckem remote` subcommand)
- Snapshot history and timeline (`pycheckem history add/show/diff`)
- Plugin system for custom collectors via entry points

## [0.2.0] - 2026-03-02

### Added
- `pycheckem compare` command — snapshot and diff in one step
- Optional rich renderer with color-coded output (`pip install pycheckem[pretty]`)
- PyPI packaging with extras (`[pretty]`, `[toml]`, `[dev]`)
- Improved help text and error messages

## [0.1.0] - 2026-03-02

### Added
- Initial release — full snapshot, diff, and render pipeline
- Seven collectors: Python info, packages, environment variables, OS info, paths, config files, project metadata
- `pycheckem snapshot` CLI command with JSON output
- `pycheckem diff` CLI command with ascii and JSON renderers
- Severity scoring (identical, minor, major, critical)
- Breaking changes detection
- CI gating with `--exit-code` and `--fail-severity`
- Sensitive environment variable filtering
- Zero external dependencies for core functionality

[0.4.0]: https://github.com/MateuszMarciszewski/Pycheckem/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/MateuszMarciszewski/Pycheckem/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/MateuszMarciszewski/Pycheckem/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MateuszMarciszewski/Pycheckem/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MateuszMarciszewski/Pycheckem/releases/tag/v0.1.0
