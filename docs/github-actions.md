# GitHub Actions Integration

Use pycheckem in CI to detect environment drift between builds, catch
unexpected dependency changes in pull requests, and gate deployments on
environment parity.

## Quick Start

Copy `.github/workflows/pycheckem-diff.yml` from this repository into
your project. The workflow:

1. Checks out the code and sets up Python.
2. Installs your project dependencies **and** pycheckem.
3. Downloads the previous baseline snapshot (stored as a GitHub artifact).
4. Snapshots the current CI environment.
5. Diffs the current snapshot against the baseline.
6. Fails the job if differences meet or exceed the severity threshold.
7. Uploads the new snapshot as the baseline on pushes to `main`.

## Creating an Initial Baseline

Before the workflow can diff, you need a baseline snapshot. Either:

- **Commit a baseline file** to your repo:

  ```bash
  pip install pycheckem
  pycheckem snapshot -o baseline.json --label baseline
  git add baseline.json && git commit -m "Add pycheckem baseline"
  ```

- **Let the workflow create one** — on the first push to `main` with no
  existing baseline, the diff step is skipped and the current snapshot
  becomes the baseline artifact.

## Severity Thresholds

Control when the CI job fails using `--fail-severity`:

| Flag                       | Fails on                                              |
|---------------------------|-------------------------------------------------------|
| `--fail-severity minor`   | Any difference at all (strictest)                     |
| `--fail-severity major`   | Python version mismatch, package downgrades/removals  |
| `--fail-severity critical`| OS mismatch, Python major version change              |

## Suppression

Ignore noisy or expected differences using `pyproject.toml` config or
CLI flags:

```toml
# pyproject.toml
[tool.pycheckem]
ignore_packages = ["pip", "setuptools", "wheel"]
ignore_env_vars = ["HOSTNAME", "PWD", "SHLVL"]
ignore_patterns = [".*_CACHE.*"]
```

Or inline in the workflow:

```yaml
- name: Diff against baseline
  run: |
    pycheckem diff baseline.json current.json \
      --exit-code \
      --fail-severity major \
      --ignore-packages pip,setuptools,wheel
```

## PR Comment Integration

You can post diff output as a PR comment using `gh`:

```yaml
- name: Post diff as PR comment
  if: github.event_name == 'pull_request' && hashFiles('baseline.json') != ''
  run: |
    DIFF_OUTPUT=$(pycheckem diff baseline.json current.json --format ascii || true)
    if [ -n "$DIFF_OUTPUT" ]; then
      gh pr comment ${{ github.event.pull_request.number }} \
        --body "### pycheckem Environment Diff
    \`\`\`
    $DIFF_OUTPUT
    \`\`\`"
    fi
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## JSON Output for Programmatic Use

Use `--format json` to parse diff results in downstream steps:

```yaml
- name: Check for breaking changes
  run: |
    pycheckem diff baseline.json current.json --format json > diff.json
    # Parse with jq, Python, or any JSON tool
    SEVERITY=$(python -c "import json; print(json.load(open('diff.json'))['summary']['severity'])")
    echo "Severity: $SEVERITY"
```

## History Tracking

Use the `history` subcommand to track environment changes over time:

```yaml
- name: Add to history
  run: pycheckem history add current.json

- name: Show history
  run: pycheckem history show

- name: Diff last 2 snapshots
  run: pycheckem history diff --last 2
```
