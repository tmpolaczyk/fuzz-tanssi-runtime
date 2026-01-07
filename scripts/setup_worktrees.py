#!/usr/bin/env python3
import argparse
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


WORKTREE_DEFAULT = "../fuzz-tanssi-runtime-wt-polkadot-sdk"
SDK_DEFAULT = "../polkadot-sdk"
TANSSI_LOCK_DEFAULT = "../tanssi/Cargo.lock"

# Patch directory (in *this* repo)
PATCHES_DIR_DEFAULT = "patches/polkadot-sdk"

TARGET_REPO = "https://github.com/moondance-labs/polkadot-sdk"
EXPECTED_SOURCE_SUBSTR = "github.com/moondance-labs/polkadot-sdk"


class CmdError(RuntimeError):
    pass


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def quote_cmd(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(x) for x in cmd)


def run_cmd(
    cmd: list[str],
    cwd: Optional[Path] = None,
    *,
    capture_stdout: bool = False,
) -> subprocess.CompletedProcess:
    """
    Run a command, never silently ignore failures.
    On error, raise with stdout/stderr attached.
    """
    try:
        cp = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture_stdout else None,
            stderr=subprocess.PIPE,
        )
        return cp
    except FileNotFoundError as ex:
        raise CmdError(f"Command not found: {cmd[0]!r}. Is it installed and on PATH?") from ex
    except subprocess.CalledProcessError as ex:
        out = ex.stdout or ""
        err = ex.stderr or ""
        msg = [
            "Command failed:",
            f"  cwd: {cwd}" if cwd else "  cwd: (default)",
            f"  cmd: {quote_cmd(cmd)}",
        ]
        if out.strip():
            msg += ["", "stdout:", out.rstrip()]
        if err.strip():
            msg += ["", "stderr:", err.rstrip()]
        raise CmdError("\n".join(msg)) from ex


def repo_is_clean(path: str, *, include_untracked: bool = False, check_ops: bool = True) -> bool:
    # 1) Single porcelain-v2 call. Lines starting with 1/2/u/?/! mean changes.
    args = [
        "git", "status", "--porcelain=v2", "--branch",
        "--untracked-files=" + ("normal" if include_untracked else "no"),
    ]
    r = subprocess.run(args, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    lines = r.stdout.splitlines()
    # ? Means untracked files, they will be ignored unless passed include_untracked=True
    # So with include_untracked=False we allow untracked files in a clean repo
    # and with include_untracked=True we dont allow untracked files, the script will abort if untracked files are found
    has_paths = any(l and l[0] in ("1", "2", "u", "?", "!") and (include_untracked or l[0] != "?") for l in lines)
    if has_paths:
        return False

    if not check_ops:
        return True

    # 2) Detect in-progress ops via well-known refs/dirs.
    def has_ref(name: str) -> bool:
        return subprocess.run(["git", "rev-parse", "-q", "--verify", name],
                              cwd=path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    if any(has_ref(ref) for ref in ("CHERRY_PICK_HEAD", "MERGE_HEAD", "REVERT_HEAD")):
        return False

    git_dir = subprocess.run(["git", "rev-parse", "--git-dir"], cwd=path,
                             stdout=subprocess.PIPE, text=True, check=True).stdout.strip()
    if any(os.path.exists(os.path.join(path, git_dir, d)) for d in ("rebase-apply", "rebase-merge")):
        return False

    return True


def git_is_repo(path: Path) -> bool:
    try:
        run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=path)
        return True
    except CmdError:
        return False


def git_head_commit(repo: Path) -> str:
    cp = run_cmd(["git", "rev-parse", "HEAD"], cwd=repo, capture_stdout=True)
    return cp.stdout.strip()


def git_commit_exists(repo: Path, rev: str) -> None:
    run_cmd(["git", "cat-file", "-e", f"{rev}^{{commit}}"], cwd=repo)


def git_is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    # exit 0 if ancestor is ancestor of descendant
    r = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=str(repo),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return r.returncode == 0


def git_worktree_list_porcelain(repo: Path) -> str:
    cp = run_cmd(["git", "worktree", "list", "--porcelain"], cwd=repo, capture_stdout=True)
    return cp.stdout


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class CargoLockPkg:
    name: str
    version: Optional[str]
    source: Optional[str]


_LOCK_KV_RE = re.compile(r'^(?P<k>[A-Za-z0-9_-]+)\s*=\s*"(?P<v>.*)"\s*$')
_GIT_REV_RE = re.compile(r"#(?P<rev>[0-9a-fA-F]{7,40})$")


def parse_cargo_lock_packages(lock_path: Path) -> list[CargoLockPkg]:
    if not lock_path.exists():
        raise RuntimeError(f"Cargo.lock not found at: {lock_path}")

    pkgs: list[CargoLockPkg] = []
    cur: dict[str, Optional[str]] | None = None

    for raw in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line == "[[package]]":
            if cur is not None:
                pkgs.append(
                    CargoLockPkg(
                        name=cur.get("name") or "",
                        version=cur.get("version"),
                        source=cur.get("source"),
                    )
                )
            cur = {"name": None, "version": None, "source": None}
            continue

        if cur is None:
            continue

        m = _LOCK_KV_RE.match(line)
        if not m:
            continue

        k = m.group("k")
        v = m.group("v")
        if k in ("name", "version", "source"):
            cur[k] = v

    if cur is not None:
        pkgs.append(
            CargoLockPkg(
                name=cur.get("name") or "",
                version=cur.get("version"),
                source=cur.get("source"),
            )
        )

    return [p for p in pkgs if p.name]


def extract_git_rev_from_source(source: str) -> str:
    m = _GIT_REV_RE.search(source)
    if not m:
        raise RuntimeError(
            "Could not extract a git revision from Cargo.lock 'source' field.\n"
            f"source = {source!r}\n"
            "Expected it to end with '#<gitrev>'."
        )
    return m.group("rev").lower()


def find_sp_core_rev(lock_path: Path) -> str:
    pkgs = parse_cargo_lock_packages(lock_path)
    candidates = [p for p in pkgs if p.name == "sp-core"]

    if not candidates:
        raise RuntimeError(f"No [[package]] entry with name='sp-core' found in {lock_path}")

    # Prefer git sources, and specifically moondance-labs/polkadot-sdk
    def score(p: CargoLockPkg) -> int:
        s = p.source or ""
        sc = 0
        if "git+" in s:
            sc += 10
        if EXPECTED_SOURCE_SUBSTR in s:
            sc += 50
        if "github.com" in s:
            sc += 1
        return sc

    candidates_sorted = sorted(candidates, key=score, reverse=True)
    best = candidates_sorted[0]

    if not best.source:
        raise RuntimeError(
            "Found sp-core in Cargo.lock but it has no 'source' field, "
            "so I can't derive the git revision to check out."
        )

    if "git+" not in best.source:
        raise RuntimeError(
            "sp-core 'source' does not look like a git dependency.\n"
            f"source = {best.source!r}\n"
            "This script expects sp-core to come from a git source with '#<rev>'."
        )

    if EXPECTED_SOURCE_SUBSTR not in best.source:
        raise RuntimeError(
            "sp-core appears to come from an unexpected source.\n"
            f"expected to contain: {EXPECTED_SOURCE_SUBSTR!r}\n"
            f"actual source:       {best.source!r}\n"
        )

    rev = extract_git_rev_from_source(best.source)

    # If multiple sp-core git entries exist with differing revs, fail loudly.
    strong = [p for p in candidates if (p.source or "").startswith("git+")]
    revs = set()
    for p in strong:
        if p.source and _GIT_REV_RE.search(p.source):
            revs.add(extract_git_rev_from_source(p.source))
    if len(revs) > 1:
        lines = ["Multiple sp-core git revisions found in Cargo.lock; refusing to guess:"]
        for p in strong:
            lines.append(f"  - sp-core {p.version or '?'} source={p.source!r}")
        raise RuntimeError("\n".join(lines))

    return rev


def prompt_for_path(prompt: str, default: Path) -> Path:
    answer = input(f"{prompt} [{default}]: ").strip()
    return (Path(answer) if answer else default).expanduser()


def ensure_worktree(
    sdk_repo: Path,
    worktree_path: Path,
    desired_rev: str,
) -> None:
    if not sdk_repo.exists():
        raise RuntimeError(f"polkadot-sdk path does not exist: {sdk_repo}")
    if not git_is_repo(sdk_repo):
        raise RuntimeError(f"{sdk_repo} is not a git repository (expected polkadot-sdk checkout).")

    # Ensure the base commit exists in the polkadot-sdk repo
    try:
        git_commit_exists(sdk_repo, desired_rev)
    except CmdError as ex:
        raise RuntimeError(
            "The desired revision from ../tanssi/Cargo.lock does not exist in your local polkadot-sdk repo.\n"
            f"  repo: {sdk_repo}\n"
            f"  rev:  {desired_rev}\n"
            "You likely need to fetch updates in that repo.\n"
            "Try: git fetch --all --tags\n"
        ) from ex

    if worktree_path.exists():
        if not git_is_repo(worktree_path):
            raise RuntimeError(
                f"Worktree path exists but is not a git repository: {worktree_path}\n"
                "Refusing to overwrite. Remove/rename it and retry."
            )
        head = git_head_commit(worktree_path)
        if not (head == desired_rev or git_is_ancestor(worktree_path, desired_rev, "HEAD")):
            raise RuntimeError(
                "Existing worktree is not based on the desired base revision.\n"
                f"  worktree: {worktree_path}\n"
                f"  HEAD:     {head}\n"
                f"  base:     {desired_rev}\n"
                "Expected base to be an ancestor of HEAD.\n"
                "Fix by removing the worktree (git worktree remove ...) or deleting the folder, then rerun."
            )
        print(f"Worktree present (base OK) at HEAD {head} -> {worktree_path}")
        return

    wt_list = git_worktree_list_porcelain(sdk_repo)
    if str(worktree_path) in wt_list:
        raise RuntimeError(
            "Git already has a worktree registered at this path, but the directory is missing.\n"
            f"  repo: {sdk_repo}\n"
            f"  path: {worktree_path}\n"
            "Run: git worktree prune\n"
            "Or remove the stale worktree entry, then rerun this script."
        )

    ensure_parent_dir(worktree_path)
    cmd = ["git", "worktree", "add", "--detach", str(worktree_path), desired_rev]
    print("Creating worktree:")
    print(" ", quote_cmd(cmd))
    run_cmd(cmd, cwd=sdk_repo)

    head = git_head_commit(worktree_path)
    if head != desired_rev:
        raise RuntimeError(
            "Worktree creation succeeded, but HEAD doesn't match desired revision.\n"
            f"  HEAD:   {head}\n"
            f"  wanted: {desired_rev}\n"
        )
    print(f"Worktree created at {head} -> {worktree_path}")


def ensure_worktree_clean_or_abort(worktree_path: Path) -> None:
    try:
        ok = repo_is_clean(str(worktree_path), include_untracked=False, check_ops=True)
    except subprocess.CalledProcessError as ex:
        raise RuntimeError(
            "Failed to check worktree cleanliness (git status failed).\n"
            f"worktree: {worktree_path}\n"
            f"error: {ex}"
        ) from ex

    if ok:
        return

    status = run_cmd(["git", "status", "--porcelain=v2", "--branch"], cwd=worktree_path, capture_stdout=True).stdout
    raise RuntimeError(
        "Worktree has unstaged/staged changes or an in-progress git operation; aborting.\n"
        f"worktree: {worktree_path}\n"
        "\n"
        "git status --porcelain=v2 --branch:\n"
        f"{status}"
    )


def git_patch_id_from_text(repo: Path, text: str) -> str:
    r = subprocess.run(
        ["git", "patch-id", "--stable"],
        cwd=str(repo),
        input=text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    line = (r.stdout or "").strip()
    if not line:
        raise RuntimeError("git patch-id produced no output (unexpected).")
    return line.split()[0]


def patch_ids_from_patch_files(repo: Path, patches: list[Path]) -> dict[str, Path]:
    """
    Returns {patch_id -> patch_file_path}
    """
    out: dict[str, Path] = {}
    for p in patches:
        content = p.read_text(encoding="utf-8", errors="replace")
        pid = git_patch_id_from_text(repo, content)
        # If duplicates exist, keep the first (but don't silently lose the fact)
        if pid in out and out[pid] != p:
            raise RuntimeError(
                "Duplicate patch-id detected among patch files.\n"
                f"  patch-id: {pid}\n"
                f"  file1:    {out[pid]}\n"
                f"  file2:    {p}\n"
                "This usually means two patches with identical diffs."
            )
        out[pid] = p
    return out


def patch_ids_from_commits(repo: Path, base_rev: str) -> set[str]:
    cp = run_cmd(["git", "rev-list", f"{base_rev}..HEAD"], cwd=repo, capture_stdout=True)
    commits = [c.strip() for c in cp.stdout.splitlines() if c.strip()]

    ids: set[str] = set()
    for c in commits:
        show = run_cmd(["git", "show", "--pretty=format:", c], cwd=repo, capture_stdout=True).stdout
        pid = git_patch_id_from_text(repo, show)
        ids.add(pid)
    return ids


def verify_patches_applied(repo: Path, base_rev: str, patches_dir: Path) -> tuple[bool, list[Path], int]:
    patches = sorted(patches_dir.glob("*.patch"))
    if not patches:
        return True, [], 0

    want_map = patch_ids_from_patch_files(repo, patches)
    have = patch_ids_from_commits(repo, base_rev)

    missing = [want_map[pid] for pid in sorted(want_map.keys()) if pid not in have]
    return (len(missing) == 0), missing, len(patches)


def apply_patches_to_worktree(
    worktree_path: Path,
    base_rev: str,
    patches_dir: Path,
) -> None:
    patches = sorted(patches_dir.glob("*.patch"))
    if not patches:
        print(f"No patches found in {patches_dir}, skipping patch application.")
        return

    head = git_head_commit(worktree_path)

    # If HEAD isn't equal to base, do a real verification instead of guessing.
    if head != base_rev:
        ok, missing, total = verify_patches_applied(worktree_path, base_rev, patches_dir)
        if ok:
            print(f"Verified: all {total} patches already present in {base_rev}..HEAD. Skipping patch application.")
            return

        missing_list = "\n".join(f"  - {p.name}" for p in missing[:20])
        more = "" if len(missing) <= 20 else f"\n  ... and {len(missing) - 20} more"
        raise RuntimeError(
            "Worktree HEAD != base revision, and patch series does NOT appear fully applied.\n"
            f"  base: {base_rev}\n"
            f"  head: {head}\n"
            f"  patches dir: {patches_dir}\n"
            "\nMissing patches (by patch-id):\n"
            f"{missing_list}{more}\n"
            "\nRefusing to guess. Either:\n"
            "  - reset/recreate the worktree at the base revision so the script can apply patches, or\n"
            "  - export/update your patch series to match what's in the worktree."
        )

    # HEAD == base, so apply the series.
    ensure_worktree_clean_or_abort(worktree_path)

    cmd = ["git", "am", "--3way", "--keep-cr"] + [str(p) for p in patches]
    print("Applying patches:")
    print(" ", quote_cmd(cmd))
    try:
        run_cmd(cmd, cwd=worktree_path)
    except CmdError as ex:
        raise RuntimeError(
            "Failed to apply patches with git am.\n"
            f"worktree: {worktree_path}\n"
            f"patches:  {patches_dir}\n"
            "\nTo recover:\n"
            f"  git -C {shlex.quote(str(worktree_path))} am --abort\n"
            "Or resolve conflicts then:\n"
            f"  git -C {shlex.quote(str(worktree_path))} am --continue\n"
            "\nOriginal error:\n"
            f"{ex}"
        ) from ex

    ensure_worktree_clean_or_abort(worktree_path)
    new_head = git_head_commit(worktree_path)
    ok, missing, total = verify_patches_applied(worktree_path, base_rev, patches_dir)
    if not ok:
        missing_list = "\n".join(f"  - {p.name}" for p in missing[:20])
        more = "" if len(missing) <= 20 else f"\n  ... and {len(missing) - 20} more"
        raise RuntimeError(
            "Applied patches, but verification failed (unexpected).\n"
            f"  base: {base_rev}\n"
            f"  head: {new_head}\n"
            f"  patches dir: {patches_dir}\n"
            "\nStill missing patches (by patch-id):\n"
            f"{missing_list}{more}\n"
        )

    print(f"Patches applied successfully. New HEAD: {new_head}")


def run_diener_patch(worktree_path: Path) -> None:
    cmd = [
        "diener",
        "patch",
        "--crates-to-patch",
        str(worktree_path) + "/",
        "--target",
        TARGET_REPO,
    ]
    print("Running diener:")
    print(" ", quote_cmd(cmd))
    run_cmd(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Ensure a polkadot-sdk worktree pinned to ../tanssi/Cargo.lock(sp-core), "
            "verify/apply local patch series to the worktree, then run diener patch."
        )
    )
    parser.add_argument(
        "--worktree-path",
        default=WORKTREE_DEFAULT,
        help=f"Where to create/find the polkadot-sdk worktree (default: {WORKTREE_DEFAULT})",
    )
    parser.add_argument(
        "--sdk-path",
        default=None,
        help=f'Path to existing "polkadot-sdk" checkout (default: ask if worktree missing; suggested: {SDK_DEFAULT})',
    )
    parser.add_argument(
        "--tanssi-cargo-lock",
        default=TANSSI_LOCK_DEFAULT,
        help=f"Path to Tanssi Cargo.lock to read sp-core revision from (default: {TANSSI_LOCK_DEFAULT})",
    )
    parser.add_argument(
        "--patches-dir",
        default=PATCHES_DIR_DEFAULT,
        help=f"Directory containing *.patch files to apply to the worktree (default: {PATCHES_DIR_DEFAULT})",
    )
    parser.add_argument(
        "--skip-apply-patches",
        action="store_true",
        help="Do not apply patches to the worktree (still checks cleanliness).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt; fail if inputs are missing.",
    )
    args = parser.parse_args()

    worktree_path = Path(args.worktree_path).resolve()
    tanssi_lock = Path(args.tanssi_cargo_lock).resolve()
    patches_dir = (Path.cwd() / args.patches_dir).resolve()

    base_rev = find_sp_core_rev(tanssi_lock)
    print(f"../tanssi/Cargo.lock sp-core revision (base): {base_rev}")

    if not worktree_path.exists():
        if args.sdk_path is not None:
            sdk_repo = Path(args.sdk_path).expanduser().resolve()
        else:
            default_sdk = (Path.cwd() / SDK_DEFAULT).resolve()
            if args.non_interactive:
                raise RuntimeError(
                    "Worktree does not exist and --sdk-path was not provided (and --non-interactive was set).\n"
                    f"Missing worktree: {worktree_path}\n"
                    "Provide --sdk-path /path/to/polkadot-sdk"
                )
            sdk_repo = prompt_for_path('Path to your "polkadot-sdk" folder', default_sdk).resolve()

        ensure_worktree(sdk_repo, worktree_path, base_rev)
    else:
        if not git_is_repo(worktree_path):
            raise RuntimeError(
                f"Worktree path exists but is not a git repo: {worktree_path}\n"
                "Refusing to proceed."
            )

        head = git_head_commit(worktree_path)
        if not (head == base_rev or git_is_ancestor(worktree_path, base_rev, "HEAD")):
            raise RuntimeError(
                "Existing worktree does not appear to be based on ../tanssi/Cargo.lock(sp-core).\n"
                f"  worktree: {worktree_path}\n"
                f"  HEAD:     {head}\n"
                f"  base:     {base_rev}\n"
            )
        print(f"Worktree verified (base OK) at HEAD {head} -> {worktree_path}")

    # Abort early if the worktree is dirty / mid-operation
    ensure_worktree_clean_or_abort(worktree_path)

    if not args.skip_apply_patches:
        apply_patches_to_worktree(worktree_path, base_rev, patches_dir)

    run_diener_patch(worktree_path)
    print("Done.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, CmdError) as ex:
        eprint(f"ERROR: {ex}")
        raise SystemExit(2)

