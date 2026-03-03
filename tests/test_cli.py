import subprocess
import sys

from pycheckem.cli import main
from pycheckem.version import __version__


class TestCLIHelp:
    def test_no_args_prints_help(self, capsys):
        main([])
        captured = capsys.readouterr()
        assert "pycheckem" in captured.out

    def test_version_flag(self, capsys):
        try:
            main(["--version"])
        except SystemExit:
            pass
        captured = capsys.readouterr()
        assert __version__ in captured.out

    def test_snapshot_command(self, capsys, tmp_path):
        outfile = str(tmp_path / "test.json")
        main(["snapshot", "-o", outfile])
        captured = capsys.readouterr()
        assert outfile in captured.out

    def test_diff_command(self, capsys, tmp_path):
        from pycheckem.snapshot import snapshot as take_snapshot, save

        snap = take_snapshot(label="test")
        file_a = str(tmp_path / "a.json")
        file_b = str(tmp_path / "b.json")
        save(snap, file_a)
        save(snap, file_b)
        main(["diff", file_a, file_b])
        captured = capsys.readouterr()
        assert "No differences" in captured.out

    def test_compare_command(self, capsys, tmp_path):
        from pycheckem.snapshot import snapshot as take_snapshot, save

        snap = take_snapshot(label="saved")
        saved_file = str(tmp_path / "saved.json")
        save(snap, saved_file)
        main(["compare", saved_file])
        captured = capsys.readouterr()
        assert "pycheckem:" in captured.out


class TestCLIEntryPoint:
    def test_python_m_pycheckem(self):
        result = subprocess.run(
            [sys.executable, "-m", "pycheckem", "--version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert __version__ in result.stdout
