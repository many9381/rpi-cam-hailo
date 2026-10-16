"""Exercise source selection through the real format gate in temporary repos."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check.sh")
FORMATTER_NAME = os.environ.get("CLANG_FORMAT") or shutil.which("clang-format-18") or shutil.which("clang-format")
FORMATTER_PATH = shutil.which(FORMATTER_NAME) if FORMATTER_NAME else None
FORMATTER = str(Path(FORMATTER_PATH).resolve()) if FORMATTER_PATH else None


class FormatGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "tools/ci").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.root / "tools/ci/check.sh")
        self.git("init", "-q")
        self.write(".clang-format", "BasedOnStyle: Google\n")
        self.write("src/existing.cpp", "int value = 1;\n")
        self.git("add", ".clang-format", "src/existing.cpp")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              capture_output=True)

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def run_gate(self):
        env = dict(os.environ, CLANG_FORMAT=str(FORMATTER), CLANG_TIDY="/bin/false")
        return subprocess.run(["bash", "tools/ci/check.sh", "--format"],
                              cwd=self.root, env=env, capture_output=True,
                              text=True, timeout=20)

    def assert_gate_passes(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_unformatted_untracked_header(self):
        self.write("include/example/New.hpp", "int    value=1;\n")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("New.hpp", result.stderr)

    def test_rejects_unformatted_untracked_test(self):
        self.write("tests/unit/NewTest.cpp", "int    value=1;\n")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_keeps_rejecting_unformatted_tracked_source(self):
        self.write("src/existing.cpp", "int    value=1;\n")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_ignores_excluded_generated_source(self):
        self.write(".gitignore", "src/generated/\n")
        self.write("src/generated/bad.cpp", "int    value=1;\n")
        self.assert_gate_passes()

    def test_ignores_deleted_tracked_source(self):
        (self.root / "src/existing.cpp").unlink()
        self.write("src/replacement.cpp", "int value = 1;\n")
        self.assert_gate_passes()

    def test_preserves_whitespace_in_source_names(self):
        for name in ("src/with space.cpp", "src/with\nnewline.cpp"):
            with self.subTest(name=name):
                path = self.write(name, "int value = 1;\n")
                self.git("add", name)
                self.assert_gate_passes()
                path.write_text("int    value=1;\n")
                self.assertNotEqual(self.run_gate().returncode, 0)
                path.write_text("int value = 1;\n")


class ToolRequirementTests(unittest.TestCase):
    def test_relative_formatter_paths_survive_fixture_working_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "bin/clang-format-18").symlink_to(FORMATTER)
            for override in ("./bin/clang-format-18", "clang-format-18", ""):
                with self.subTest(override=override):
                    env = dict(os.environ, CLANG_FORMAT=override,
                               PATH="bin:" + os.environ.get("PATH", ""))
                    result = subprocess.run(
                        [sys.executable, str(Path(__file__).resolve()), "FormatGateTests"],
                        cwd=root, env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_formatter_fails_instead_of_skipping_gate(self):
        with tempfile.TemporaryDirectory() as empty_path:
            env = dict(os.environ, PATH=empty_path, CLANG_FORMAT="")
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                     "FormatGateTests"],
                                    env=env, capture_output=True, text=True,
                                    timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clang-format", result.stderr)


if __name__ == "__main__":
    if not FORMATTER:
        raise SystemExit("clang-format 18+ is required; set CLANG_FORMAT")
    unittest.main()
