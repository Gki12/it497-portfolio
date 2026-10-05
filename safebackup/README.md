# safebackup — verified, privacy-aware folder backups

Gaston Kasongo · IT 497 Capstone · Automation and Reliability Project (refined, version 2)

It's a small Python tool that uses only the standard library. Every backup is checked before the tool reports success. Files that look like passwords or keys are left out unless you choose to include them. Nothing is ever deleted without your confirmation.

## Requirements
Python 3.9 or newer. No packages to install.

## Usage
```bash
python safebackup.py backup  <source-folder> <backup-folder>   # make a verified snapshot
python safebackup.py verify  <backup-folder>                   # re-check the latest snapshot
python safebackup.py restore <backup-folder> <empty-folder>    # verified restore
python safebackup.py prune   <backup-folder> --keep 7          # dry run; add --apply to delete
```
Options: `--exclude PATTERN` (repeatable), `--include-sensitive`, `--snapshot NAME`, `--overwrite`, `-q/--quiet`.

## Exit codes
| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Bad arguments or a folder was not found |
| 3 | Integrity check failed |
| 4 | An unsafe action was refused (overwrite, path escape, backup inside source) |
| 5 | Not enough free space |

## Tests
```bash
python -m unittest -v test_safebackup
```
There are 13 tests. They cover a successful backup, a missing source, secret exclusion and opt-in, a restore round trip, tamper detection, overwrite protection, path traversal, a prune dry run, log privacy, a backup folder inside the source, symlinks, and cleanup after a failure. All test data is fictional.

## Known limitations
- Snapshots are not encrypted. Keep the backup folder on storage you control, such as an encrypted drive. Encryption is planned for version 3.
- Each snapshot is a full copy. There are no incremental backups.
- File permissions and ownership are only partly kept (`shutil.copy2`).
- `v1_backup.py` stays in the repository on purpose as the baseline for comparison. Do not use it.
