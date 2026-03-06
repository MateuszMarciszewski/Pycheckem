# pycheckem-mcp

MCP (Model Context Protocol) server for [pycheckem](https://pypi.org/project/pycheckem/). Lets AI coding assistants like Claude Code, Cursor, and Windsurf snapshot and diff Python environments directly.

## Install

```bash
pip install pycheckem-mcp
```

Or with pipx:

```bash
pipx install pycheckem-mcp
```

## Configure

Add to your Claude Code or Cursor MCP config:

```json
{
  "mcpServers": {
    "pycheckem": {
      "command": "pycheckem-mcp"
    }
  }
}
```

Or if using pipx:

```json
{
  "mcpServers": {
    "pycheckem": {
      "command": "pipx",
      "args": ["run", "pycheckem-mcp"]
    }
  }
}
```

## Tools

### `snapshot_environment`
Capture the current Python environment (packages, versions, OS, env vars) to a JSON file.

### `diff_environments`
Compare two saved snapshot files and report all differences.

### `compare_environment`
Compare the current live environment against a saved baseline snapshot.

### `verify_dependencies`
Check if installed packages satisfy a requirements.txt or pyproject.toml.

## License

MIT
