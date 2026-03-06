Capture a snapshot of the current Python environment.

Run `pycheckem snapshot -o environment-baseline.json --label baseline` to
record all installed packages and their versions, Python version, OS info,
environment variables, and sys.path.

This baseline can be used later with `pycheckem guard` to detect drift,
or with `pycheckem diff` to compare against another environment.
