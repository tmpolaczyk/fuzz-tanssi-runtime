#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
from pathlib import Path

SRC_DEFAULT = "fuzzers/fuzz-dancelight/fuzz/corpus"
DST_DEFAULT = "fuzzers/fuzz-starlight/fuzz/corpus"

def try_rsync(src: Path, dst: Path) -> bool:
    """
    Use rsync to copy only missing files, preserving structure and metadata.
    Returns True if rsync succeeded, False otherwise.
    """
    if shutil.which("rsync") is None:
        return False
    # Trailing slashes => copy *contents* of src into dst/
    cmd = ["rsync", "-a", "--ignore-existing", str(src) + os.sep, str(dst) + os.sep]
    try:
        subprocess.run(cmd, check=True)
        print(f"Completed via rsync into {dst}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"rsync failed (falling back to Python copy): {e}")
        return False

def naive_copy(src_root: Path, dst_root: Path):
    """
    Single-threaded, simple copy: only copies files that don't exist at destination.
    """
    copied = 0
    skipped = 0
    errors = 0

    for dirpath, _, filenames in os.walk(src_root):
        sp = Path(dirpath)
        rel_dir = sp.relative_to(src_root)
        for name in filenames:
            s = sp / name
            d = dst_root / rel_dir / name
            if d.exists():
                skipped += 1
                continue
            try:
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, d)
                copied += 1
            except Exception as e:
                errors += 1
                print(f"Error copying {s} -> {d}: {e}")

    print(f"Completed (fallback). Copied: {copied}, Skipped: {skipped}, Errors: {errors}")

def main():
    ap = argparse.ArgumentParser(
        description="Copy missing corpus files from dancelight to starlight (rsync fast path; naive fallback)."
    )
    ap.add_argument("--src", default=SRC_DEFAULT, help="Source corpus directory")
    ap.add_argument("--dst", default=DST_DEFAULT, help="Destination corpus directory")
    args = ap.parse_args()

    src = Path(args.src)
    dst = Path(args.dst)

    if not src.is_dir():
        raise SystemExit(f"Source not found or not a directory: {src}")
    dst.mkdir(parents=True, exist_ok=True)

    if try_rsync(src, dst):
        return

    naive_copy(src, dst)

if __name__ == "__main__":
    main()
