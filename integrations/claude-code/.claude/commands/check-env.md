Check if the current Python environment matches the project's requirements.

Run pycheckem to compare the active environment against the project's
requirements file. Look for requirements.txt, pyproject.toml, or Pipfile.lock
in the project root. If pycheckem is not installed, install it first with
`pip install pycheckem`.

Use: `pycheckem verify <requirements_file> --exit-code`

Report any missing packages, version mismatches, or extra packages. If the
environment is satisfied, confirm that everything looks good.
