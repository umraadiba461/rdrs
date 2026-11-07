"""SAFE ransomware simulator for testing RDRS.

It only CREATES new files full of random bytes (which look encrypted) and renames
them to .locked, inside a folder that must be named "sandbox". It never reads,
changes or deletes any of your existing files.

    python scripts/simulate_ransomware.py                       # 40 files in data/sandbox
    python scripts/simulate_ransomware.py --count 60 --delay 0.03
    python scripts/simulate_ransomware.py --cleanup             # remove only the sim_* files
"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path


def check_folder(folder: Path) -> None:
    if folder.name != "sandbox":
        raise SystemExit(f"Refusing to run: the folder must be named 'sandbox' (got '{folder.name}').")


def simulate(folder: Path, count: int = 40, size: int = 20000, delay: float = 0.02) -> int:
    """Write `count` random files, then rename each one to .locked. Returns how many."""
    check_folder(folder)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    made = []
    for i in range(1, count + 1):
        path = folder / f"sim_{stamp}_{i}.txt"
        path.write_bytes(os.urandom(size))
        made.append(path)
        time.sleep(delay)
    for path in made:
        path.rename(path.with_suffix(".locked"))
        time.sleep(delay)
    return len(made)


def cleanup(folder: Path) -> int:
    """Delete only the files this script created (names starting with sim_)."""
    check_folder(folder)
    removed = 0
    for path in folder.glob("sim_*"):
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe ransomware simulator for RDRS")
    parser.add_argument("--folder", default="data/sandbox")
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--delay", type=float, default=0.02)
    parser.add_argument("--cleanup", action="store_true", help="remove the sim_* files and exit")
    args = parser.parse_args()
    folder = Path(args.folder)
    if args.cleanup:
        print(f"Removed {cleanup(folder)} simulated files from {folder}")
    else:
        print(f"Simulated an attack on {simulate(folder, args.count, delay=args.delay)} files in {folder}")


if __name__ == "__main__":
    main()