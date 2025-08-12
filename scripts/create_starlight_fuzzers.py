#!/usr/bin/env python3
import argparse
import os
import subprocess
import shutil
from pathlib import Path


SRC_DIR_DEFAULT = "fuzzers/fuzz-dancelight"
DST_DIR_DEFAULT = "fuzzers/fuzz-starlight"
FROM_STR_DEFAULT = "dancelight"
TO_STR_DEFAULT = "starlight"


def git_tracked_files(src_dir: str) -> list[Path]:
    """
    Return a list of git-tracked files under src_dir, using `git ls-files`.
    """
    try:
        res = subprocess.run(
            ["git", "ls-files", "-z", "--", src_dir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        msg = e.stderr.decode("utf-8", errors="ignore")
        raise SystemExit(f"Failed to list git-tracked files under {src_dir}: {msg}") from e

    out = res.stdout.decode("utf-8", errors="strict")
    paths = [Path(p) for p in out.split("\0") if p]
    return paths


def copy_tracked(src_dir: str, dst_dir: str) -> int:
    """
    Copy all git-tracked files from src_dir to dst_dir, preserving metadata.
    Does NOT delete anything in dst_dir; overwrites files if they exist.
    """
    files = git_tracked_files(src_dir)
    copied = 0
    for src_path in files:
        rel = src_path.relative_to(src_dir)
        dst_path = Path(dst_dir) / rel
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        copied += 1
    print(f"Copied {copied} tracked file(s) from '{src_dir}' to '{dst_dir}'.")
    return copied


def is_text_file(path: Path, sample_size: int = 8192) -> bool:
    """
    Heuristic text check: reject if NUL byte present; require UTF-8 decodability.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        if b"\x00" in chunk:
            return False
        chunk.decode("utf-8")
        return True
    except Exception:
        return False


def replace_in_tree(root: str, needle: str, replacement: str) -> int:
    """
    Replace all occurrences of 'needle' with 'replacement' in text files under 'root'.
    """
    modified = 0
    scanned = 0
    root_path = Path(root)

    for dirpath, _, filenames in os.walk(root_path):
        dirpath = Path(dirpath)
        if ".git" in dirpath.parts:
            continue
        for fn in filenames:
            path = dirpath / fn
            if not path.is_file():
                continue
            scanned += 1
            if not is_text_file(path):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue
            if needle in text:
                new_text = text.replace(needle, replacement)
                if new_text != text:
                    path.write_text(new_text, encoding="utf-8")
                    modified += 1

    print(
        f"Search & replace '{needle}' -> '{replacement}' completed in '{root}'. "
        f"Modified {modified} file(s); scanned {scanned}."
    )
    return modified


def rename_paths_in_tree(root: str, needle: str, replacement: str) -> int:
    """
    Rename any files and directories under 'root' whose NAMES contain 'needle',
    replacing it with 'replacement'. Walks bottom-up to safely rename dirs.
    For files: overwrites existing destination files (os.replace).
    For dirs: if destination already exists, skips that rename.
    Returns number of rename operations performed.
    """
    renames = 0
    root_path = Path(root)

    # Files first (bottom-up walk also yields files)
    for dirpath, dirnames, filenames in os.walk(root_path, topdown=False):
        dirpath_p = Path(dirpath)
        if ".git" in dirpath_p.parts:
            continue

        # Rename files
        for name in filenames:
            if needle not in name:
                continue
            old = dirpath_p / name
            new = old.with_name(name.replace(needle, replacement))
            if old == new:
                continue
            new.parent.mkdir(parents=True, exist_ok=True)
            try:
                # overwrite if target exists
                os.replace(old, new)
                renames += 1
            except Exception as e:
                print(f"Warning: failed to rename file '{old}' -> '{new}': {e}")

        # Rename directories
        for name in dirnames:
            if needle not in name:
                continue
            old = dirpath_p / name
            new = old.with_name(name.replace(needle, replacement))
            if old == new:
                continue
            if new.exists():
                # Avoid risky merges; children were already processed.
                print(f"Note: target dir exists, skipping rename '{old}' -> '{new}'")
                continue
            try:
                old.rename(new)
                renames += 1
            except Exception as e:
                print(f"Warning: failed to rename dir '{old}' -> '{new}': {e}")

    print(f"Renamed {renames} path(s) under '{root}'.")
    return renames


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Create starlight fuzzers by copying git-tracked files from "
            f"'{SRC_DIR_DEFAULT}' to '{DST_DIR_DEFAULT}', renaming paths, and rewriting identifiers."
        )
    )
    parser.add_argument("--source", default=SRC_DIR_DEFAULT, help="Source directory (git-tracked files only).")
    parser.add_argument(
        "--dest",
        default=DST_DIR_DEFAULT,
        help="Destination directory. Existing files are kept; incoming files overwrite.",
    )
    parser.add_argument("--from-str", default=FROM_STR_DEFAULT, help="String to search for in names and file contents.")
    parser.add_argument("--to-str", default=TO_STR_DEFAULT, help="Replacement string for names and file contents.")
    parser.add_argument("--no-rewrite", action="store_true", help="Skip the content rewrite step.")
    parser.add_argument("--no-rename", action="store_true", help="Skip the path (file/dir name) rename step.")
    args = parser.parse_args()

    src_dir = args.source
    dst_dir = args.dest

    if not Path(src_dir).is_dir():
        raise SystemExit(f"Source directory not found: {src_dir}")

    Path(dst_dir).mkdir(parents=True, exist_ok=True)

    copy_tracked(src_dir, dst_dir)

    if not args.no_rename:
        rename_paths_in_tree(dst_dir, args.from_str, args.to_str)

    if not args.no_rewrite:
        replace_in_tree(dst_dir, args.from_str, args.to_str)


if __name__ == "__main__":
    main()
