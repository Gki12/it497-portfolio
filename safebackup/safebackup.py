"""safebackup.py — version 2 (refined).

A small, standard-library-only backup tool built for trustworthy results:

  backup   Copy a folder into a timestamped snapshot with a SHA-256 manifest.
  verify   Re-hash a snapshot and report any missing, changed, or extra files.
  restore  Verify a snapshot, then restore it to a new or empty folder.
  prune    Show (or, with --apply, delete) snapshots beyond a retention limit.

Design principles (see REFINEMENT_REPORT.md):
  * Honesty     - a backup is only reported as successful after it is verified.
  * Stewardship - likely secrets are excluded unless the user explicitly opts in;
                  logs never record file contents or the user's home path.
  * Safety      - snapshots are written atomically; restores never overwrite
                  existing files or write outside the chosen folder;
                  deletion is a dry run unless --apply is given.
  * Clarity     - plain-language messages and documented exit codes.

Author: Gaston Kasongo (IT 497). Uses only the Python standard library.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

VERSION = "2.0"
MANIFEST = "manifest.json"
LOG_FILE = "safebackup.log.jsonl"
SNAPSHOT_PREFIX = "snapshot_"

# Exit codes (documented in README so scripts and schedulers can react).
EXIT_OK = 0
EXIT_USAGE = 2          # bad arguments, missing or invalid folders
EXIT_VERIFY_FAILED = 3  # integrity problem detected
EXIT_UNSAFE = 4         # refused an unsafe action (overwrite, path escape)
EXIT_NO_SPACE = 5       # not enough free space

# Files that commonly hold credentials or private keys. Excluded by default.
SENSITIVE_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.p12", "id_rsa", "id_rsa*",
    "id_ed25519*", "*.kdbx", "credentials*", "*secret*", ".git-credentials",
    ".netrc", "*.ovpn",
]
ALWAYS_SKIP = [MANIFEST, LOG_FILE, "__pycache__", "*.partial"]


class BackupError(Exception):
    """An expected failure with a plain-language message and exit code."""

    def __init__(self, message: str, code: int = EXIT_USAGE):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- helpers
def redact(path: Path | str) -> str:
    """Replace the user's home folder with '~' so logs do not expose names."""
    text = str(path)
    home = str(Path.home())
    return "~" + text[len(home):] if home and text.startswith(home) else text


def sha256_of(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def matches(name: str, patterns: list[str]) -> bool:
    lower = name.lower()
    return any(fnmatch.fnmatch(lower, p.lower()) for p in patterns)


def log_event(dest: Path, event: dict) -> None:
    """Append one JSON line to the destination log (metadata only)."""
    event = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "version": VERSION, **event}
    with open(dest / LOG_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def say(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(message)


def snapshots(dest: Path) -> list[Path]:
    """Completed snapshots (those with a manifest), oldest first."""
    found = [p for p in dest.iterdir()
             if p.is_dir() and p.name.startswith(SNAPSHOT_PREFIX)
             and not p.name.endswith(".partial") and (p / MANIFEST).is_file()]
    return sorted(found, key=lambda p: p.name)


# ---------------------------------------------------------------- collect
def collect(source: Path, include_sensitive: bool, extra_excludes: list[str]):
    """Walk the source without following symlinks.

    Returns (files, skipped) where files is a list of relative POSIX paths and
    skipped counts the reasons files were left out.
    """
    files: list[str] = []
    skipped = {"sensitive": [], "symlink": 0, "excluded": 0, "unreadable": 0}
    patterns = list(extra_excludes)
    for root, dirs, names in os.walk(source, followlinks=False):
        root_path = Path(root)
        kept_dirs = []
        for d in dirs:
            p = root_path / d
            if p.is_symlink():
                skipped["symlink"] += 1
            elif matches(d, ALWAYS_SKIP + patterns):
                skipped["excluded"] += 1
            else:
                kept_dirs.append(d)
        dirs[:] = sorted(kept_dirs)
        for name in sorted(names):
            p = root_path / name
            rel = p.relative_to(source).as_posix()
            if p.is_symlink():
                skipped["symlink"] += 1
            elif matches(name, ALWAYS_SKIP + patterns):
                skipped["excluded"] += 1
            elif not include_sensitive and matches(name, SENSITIVE_PATTERNS):
                skipped["sensitive"].append(rel)
            elif not os.access(p, os.R_OK):
                skipped["unreadable"] += 1
            else:
                files.append(rel)
    return files, skipped


# ---------------------------------------------------------------- commands
def cmd_backup(args) -> int:
    source = Path(args.source).expanduser().resolve()
    dest = Path(args.dest).expanduser().resolve()
    if not source.is_dir():
        raise BackupError(f"The source folder was not found: {redact(source)}. "
                          "Check the spelling and try again.")
    if dest == source or source in dest.parents:
        raise BackupError("The destination cannot be inside the source folder; "
                          "the backup would copy itself.", EXIT_UNSAFE)
    dest.mkdir(parents=True, exist_ok=True)

    files, skipped = collect(source, args.include_sensitive, args.exclude or [])
    total = sum((source / f).stat().st_size for f in files)
    free = shutil.disk_usage(dest).free
    if total > free:
        raise BackupError(f"Not enough free space: need {total:,} bytes, "
                          f"{free:,} available.", EXIT_NO_SPACE)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    final = dest / f"{SNAPSHOT_PREFIX}{stamp}"
    partial = dest / f"{final.name}.partial"
    partial.mkdir()
    entries = []
    try:
        for rel in files:
            src = source / rel
            out = partial / PurePosixPath(rel)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, out)
            entries.append({"path": rel, "size": out.stat().st_size,
                            "sha256": sha256_of(out),
                            "source_sha256": sha256_of(src)})
        mismatched = [e["path"] for e in entries
                      if e["sha256"] != e.pop("source_sha256")]
        if mismatched:
            raise BackupError("Copied files did not match the originals "
                              f"(possibly changed during backup): {mismatched[:5]}",
                              EXIT_VERIFY_FAILED)
        manifest = {"tool": "safebackup", "version": VERSION,
                    "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "source": redact(source), "file_count": len(entries),
                    "total_bytes": total, "files": entries,
                    "skipped": {"sensitive_count": len(skipped["sensitive"]),
                                "symlinks": skipped["symlink"],
                                "excluded": skipped["excluded"],
                                "unreadable": skipped["unreadable"]}}
        (partial / MANIFEST).write_text(json.dumps(manifest, indent=2), "utf-8")
        partial.rename(final)  # atomic on the same file system
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise

    log_event(dest, {"action": "backup", "result": "ok", "snapshot": final.name,
                     "files": len(entries), "bytes": total,
                     "sensitive_skipped": len(skipped["sensitive"])})
    say(f"Backup complete and verified: {len(entries)} files "
        f"({total:,} bytes) saved to {final.name}.", args.quiet)
    if skipped["sensitive"]:
        say(f"Left out {len(skipped['sensitive'])} file(s) that look like "
            "passwords or keys:", args.quiet)
        for rel in skipped["sensitive"][:10]:
            say(f"  - {rel}", args.quiet)
        say("  Store secrets in a password manager, or rerun with "
            "--include-sensitive if you are sure.", args.quiet)
    if skipped["symlink"] or skipped["unreadable"]:
        say(f"Also skipped {skipped['symlink']} shortcut(s)/symlink(s) and "
            f"{skipped['unreadable']} unreadable file(s).", args.quiet)
    return EXIT_OK


def verify_snapshot(snapshot: Path) -> dict:
    manifest_path = snapshot / MANIFEST
    if not manifest_path.is_file():
        raise BackupError(f"{snapshot.name} has no manifest; it may be "
                          "incomplete or not a safebackup snapshot.",
                          EXIT_VERIFY_FAILED)
    manifest = json.loads(manifest_path.read_text("utf-8"))
    listed = {e["path"]: e for e in manifest["files"]}
    missing, changed = [], []
    for rel, entry in listed.items():
        p = snapshot / PurePosixPath(rel)
        if not p.is_file():
            missing.append(rel)
        elif sha256_of(p) != entry["sha256"]:
            changed.append(rel)
    present = {p.relative_to(snapshot).as_posix()
               for p in snapshot.rglob("*") if p.is_file()} - {MANIFEST}
    extra = sorted(present - set(listed))
    return {"manifest": manifest, "missing": missing,
            "changed": changed, "extra": extra}


def resolve_snapshot(dest: Path, name: str | None) -> Path:
    if not dest.is_dir():
        raise BackupError(f"Backup folder not found: {redact(dest)}")
    if name in (None, "latest"):
        found = snapshots(dest)
        if not found:
            raise BackupError("No completed snapshots were found.")
        return found[-1]
    snap = (dest / name).resolve()
    if snap.parent != dest or not snap.is_dir():
        raise BackupError(f"Snapshot not found: {name}")
    return snap


def cmd_verify(args) -> int:
    dest = Path(args.dest).expanduser().resolve()
    snap = resolve_snapshot(dest, args.snapshot)
    result = verify_snapshot(snap)
    ok = not (result["missing"] or result["changed"] or result["extra"])
    log_event(dest, {"action": "verify", "snapshot": snap.name,
                     "result": "ok" if ok else "failed",
                     "missing": len(result["missing"]),
                     "changed": len(result["changed"]),
                     "extra": len(result["extra"])})
    if ok:
        say(f"{snap.name}: all {result['manifest']['file_count']} files "
            "match their recorded checksums.", args.quiet)
        return EXIT_OK
    print(f"{snap.name}: verification FAILED.")
    for label in ("missing", "changed", "extra"):
        for rel in result[label][:10]:
            print(f"  {label}: {rel}")
    return EXIT_VERIFY_FAILED


def cmd_restore(args) -> int:
    dest = Path(args.dest).expanduser().resolve()
    snap = resolve_snapshot(dest, args.snapshot)
    target = Path(args.target).expanduser().resolve()
    result = verify_snapshot(snap)
    if result["missing"] or result["changed"]:
        raise BackupError(f"{snap.name} failed verification, so nothing was "
                          "restored. Run 'verify' for details.", EXIT_VERIFY_FAILED)
    if target.exists() and any(target.iterdir()) and not args.overwrite:
        raise BackupError("The restore folder is not empty. Choose an empty "
                          "folder, or add --overwrite to replace matching files.",
                          EXIT_UNSAFE)
    restored = 0
    for entry in result["manifest"]["files"]:
        rel = PurePosixPath(entry["path"])
        out = (target / rel).resolve()
        if rel.is_absolute() or ".." in rel.parts or target not in out.parents:
            raise BackupError(f"Refused unsafe path in manifest: {rel}", EXIT_UNSAFE)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(snap / rel, out)
        if sha256_of(out) != entry["sha256"]:
            raise BackupError(f"Restored copy of {rel} did not match its checksum.",
                              EXIT_VERIFY_FAILED)
        restored += 1
    log_event(dest, {"action": "restore", "snapshot": snap.name,
                     "result": "ok", "files": restored})
    say(f"Restored and verified {restored} files from {snap.name}.", args.quiet)
    return EXIT_OK


def cmd_prune(args) -> int:
    dest = Path(args.dest).expanduser().resolve()
    if args.keep < 1:
        raise BackupError("--keep must be at least 1 so one backup always remains.")
    found = snapshots(dest)
    doomed = found[:-args.keep] if len(found) > args.keep else []
    if not doomed:
        say(f"Nothing to remove: {len(found)} snapshot(s), keeping {args.keep}.",
            args.quiet)
        return EXIT_OK
    verb = "Removing" if args.apply else "Would remove (dry run)"
    for snap in doomed:
        say(f"{verb}: {snap.name}", args.quiet)
        if args.apply:
            shutil.rmtree(snap)
    if not args.apply:
        say("No files were deleted. Add --apply to delete these snapshots.",
            args.quiet)
    log_event(dest, {"action": "prune", "applied": args.apply,
                     "removed": len(doomed) if args.apply else 0,
                     "candidates": len(doomed)})
    return EXIT_OK


# ---------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safebackup",
        description="Verified, privacy-aware folder backups.")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print errors")
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("backup", help="create a verified snapshot")
    b.add_argument("source"), b.add_argument("dest")
    b.add_argument("--exclude", action="append", metavar="PATTERN",
                   help="extra file/folder pattern to skip (repeatable)")
    b.add_argument("--include-sensitive", action="store_true",
                   help="also copy files that look like passwords or keys")
    b.set_defaults(func=cmd_backup)

    v = sub.add_parser("verify", help="check a snapshot against its manifest")
    v.add_argument("dest"), v.add_argument("--snapshot", default="latest")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("restore", help="restore a verified snapshot")
    r.add_argument("dest"), r.add_argument("target")
    r.add_argument("--snapshot", default="latest")
    r.add_argument("--overwrite", action="store_true",
                   help="allow restoring into a non-empty folder")
    r.set_defaults(func=cmd_restore)

    p = sub.add_parser("prune", help="apply a retention limit")
    p.add_argument("dest"), p.add_argument("--keep", type=int, default=7)
    p.add_argument("--apply", action="store_true",
                   help="actually delete (default is a dry run)")
    p.set_defaults(func=cmd_prune)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BackupError as err:
        print(f"Error: {err}", file=sys.stderr)
        return err.code
    except PermissionError as err:
        print(f"Error: permission denied for {redact(err.filename or '')}.",
              file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
