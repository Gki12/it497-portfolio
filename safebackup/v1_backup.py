"""backup.py — version 1 (baseline, Week 2 plan).

Copies a source folder into a timestamped folder under a destination.
Kept unchanged in the repository so the refinements in v2 can be compared.
Known weaknesses are documented in REFINEMENT_REPORT.md.
"""
import shutil
import sys
from datetime import datetime


def main():
    source = sys.argv[1]
    dest = sys.argv[2]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = f"{dest}/backup_{stamp}"
    shutil.copytree(source, target)
    print(f"Backed up {source} to {target}")


if __name__ == "__main__":
    main()
