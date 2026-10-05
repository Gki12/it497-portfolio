"""Tests for safebackup v2. Run with:  python -m unittest -v test_safebackup
All test data is fictional and created in temporary folders."""
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import safebackup as sb


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = sb.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class SafeBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.src, self.dest = base / "src", base / "backups"
        (self.src / "docs").mkdir(parents=True)
        (self.src / "docs" / "notes.txt").write_text("fictional meeting notes")
        (self.src / "report.csv").write_text("id,value\n1,42\n")
        (self.src / ".env").write_text("API_KEY=not-a-real-key")
        (self.src / "server.pem").write_text("-----FAKE KEY-----")

    def tearDown(self):
        self.tmp.cleanup()

    def latest(self):
        return sb.snapshots(self.dest)[-1]

    # 1. Successful backup creates a verified snapshot with a manifest.
    def test_backup_success(self):
        code, out, _ = run("backup", str(self.src), str(self.dest))
        self.assertEqual(code, sb.EXIT_OK)
        self.assertIn("verified", out)
        manifest = json.loads((self.latest() / sb.MANIFEST).read_text())
        self.assertEqual(manifest["file_count"], 2)
        data = (self.latest() / "report.csv").read_bytes()
        entry = next(e for e in manifest["files"] if e["path"] == "report.csv")
        self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())

    # 2. Missing source gives a clear message and usage exit code.
    def test_missing_source(self):
        code, _, err = run("backup", str(self.src / "nope"), str(self.dest))
        self.assertEqual(code, sb.EXIT_USAGE)
        self.assertIn("source folder was not found", err)

    # 3. Secrets are excluded by default and reported by name only.
    def test_sensitive_excluded_by_default(self):
        _, out, _ = run("backup", str(self.src), str(self.dest))
        self.assertFalse((self.latest() / ".env").exists())
        self.assertFalse((self.latest() / "server.pem").exists())
        self.assertIn("look like passwords or keys", out)
        self.assertNotIn("not-a-real-key", out)

    # 4. Explicit opt-in includes them.
    def test_sensitive_opt_in(self):
        run("backup", str(self.src), str(self.dest), "--include-sensitive")
        self.assertTrue((self.latest() / ".env").exists())

    # 5. Restore round-trip produces identical files.
    def test_restore_round_trip(self):
        run("backup", str(self.src), str(self.dest))
        target = Path(self.tmp.name) / "restored"
        code, out, _ = run("restore", str(self.dest), str(target))
        self.assertEqual(code, sb.EXIT_OK)
        self.assertEqual((target / "docs" / "notes.txt").read_text(),
                         "fictional meeting notes")

    # 6. Tampering is detected and blocks restore.
    def test_tamper_detected(self):
        run("backup", str(self.src), str(self.dest))
        (self.latest() / "report.csv").write_text("id,value\n1,999\n")
        code, out, _ = run("verify", str(self.dest))
        self.assertEqual(code, sb.EXIT_VERIFY_FAILED)
        self.assertIn("changed: report.csv", out)
        code, _, err = run("restore", str(self.dest),
                           str(Path(self.tmp.name) / "r2"))
        self.assertEqual(code, sb.EXIT_VERIFY_FAILED)

    # 7. Restore refuses to overwrite a non-empty folder.
    def test_restore_no_overwrite(self):
        run("backup", str(self.src), str(self.dest))
        target = Path(self.tmp.name) / "busy"
        target.mkdir()
        (target / "keep.txt").write_text("important")
        code, _, err = run("restore", str(self.dest), str(target))
        self.assertEqual(code, sb.EXIT_UNSAFE)
        self.assertEqual((target / "keep.txt").read_text(), "important")

    # 8. A manifest path that escapes the restore folder is refused.
    def test_path_traversal_refused(self):
        run("backup", str(self.src), str(self.dest))
        snap = self.latest()
        evil = self.dest / "evil.txt"
        evil.write_text("x")
        manifest = json.loads((snap / sb.MANIFEST).read_text())
        manifest["files"].append({"path": "../evil.txt", "size": 1,
                                  "sha256": hashlib.sha256(b"x").hexdigest()})
        (snap / sb.MANIFEST).write_text(json.dumps(manifest))
        target = Path(self.tmp.name) / "r3"
        code, _, err = run("restore", str(self.dest), str(target))
        self.assertEqual(code, sb.EXIT_UNSAFE)
        self.assertFalse((Path(self.tmp.name) / "evil.txt").exists())

    # 9. Prune is a dry run unless --apply is given.
    def test_prune_dry_run_then_apply(self):
        for _ in range(3):
            run("backup", str(self.src), str(self.dest))
        _, out, _ = run("prune", str(self.dest), "--keep", "1")
        self.assertIn("No files were deleted", out)
        self.assertEqual(len(sb.snapshots(self.dest)), 3)
        run("prune", str(self.dest), "--keep", "1", "--apply")
        self.assertEqual(len(sb.snapshots(self.dest)), 1)

    # 10. Logs contain metadata only: no file contents, no home path.
    def test_log_privacy(self):
        run("backup", str(self.src), str(self.dest))
        log = (self.dest / sb.LOG_FILE).read_text()
        self.assertNotIn("not-a-real-key", log)
        self.assertNotIn("fictional meeting notes", log)
        self.assertNotIn(".env", log)

    # 11. Destination inside source is refused.
    def test_dest_inside_source(self):
        code, _, err = run("backup", str(self.src), str(self.src / "bk"))
        self.assertEqual(code, sb.EXIT_UNSAFE)

    # 12. Symlinks are skipped, not followed.
    @unittest.skipIf(os.name == "nt", "symlinks need admin rights on Windows")
    def test_symlink_skipped(self):
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("should not be copied")
        (self.src / "link.txt").symlink_to(outside)
        run("backup", str(self.src), str(self.dest))
        self.assertFalse((self.latest() / "link.txt").exists())

    # 13. No half-finished snapshot is left behind after a failure.
    def test_no_partial_left_on_failure(self):
        original = sb.sha256_of
        calls = {"n": 0}

        def flaky(path, chunk=1024 * 1024):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError("simulated disk error")
            return original(path, chunk)

        sb.sha256_of = flaky
        try:
            with self.assertRaises(OSError):
                run("backup", str(self.src), str(self.dest))
        finally:
            sb.sha256_of = original
        leftovers = [p for p in self.dest.iterdir() if p.is_dir()]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
