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


# Worktrees live under this directory now:
#   ../fuzz-tanssi-runtime-wt/polkadot-sdk
#   ../fuzz-tanssi-runtime-wt/tanssi
POLKADOT_SDK_WORKTREE_DEFAULT = "../fuzz-tanssi-runtime-wt/polkadot-sdk"
TANSSI_WORKTREE_DEFAULT = "../fuzz-tanssi-runtime-wt/tanssi"

# Local “source” repos from which we create worktrees
POLKADOT_SDK_REPO_DEFAULT = "../polkadot-sdk"
TANSSI_REPO_DEFAULT = "../tanssi"

# Lockfile used to determine polkadot-sdk pinned base commit:
# polkadot-sdk base is read from ../tanssi/Cargo.lock (sp-core source rev)
TANSSI_LOCK_DEFAULT = "../tanssi/Cargo.lock"

# Patch directories (in *this* repo)
POLKADOT_SDK_PATCHES_DIR_DEFAULT = "patches/polkadot-sdk"
TANSSI_PATCHES_DIR_DEFAULT = "patches/tanssi"

# Diener patch targets
POLKADOT_SDK_TARGET_REPO = "https://github.com/moondance-labs/polkadot-sdk"
TANSSI_TARGET_REPO = "https://github.com/moondance-labs/tanssi"

# Expected substrings inside Cargo.lock `source = "git+...#<rev>"`
POLKADOT_SDK_EXPECTED_SOURCE_SUBSTR = "github.com/moondance-labs/polkadot-sdk"


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
        return subprocess.run(
            ["git", "rev-parse", "-q", "--verify", name],
            cwd=path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0

    if any(has_ref(ref) for ref in ("CHERRY_PICK_HEAD", "MERGE_HEAD", "REVERT_HEAD")):
        return False

    git_dir = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=path,
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
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


def prompt_for_path(prompt: str, default: Path) -> Path:
    answer = input(f"{prompt} [{default}]: ").strip()
    return (Path(answer) if answer else default).expanduser()


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

    status = run_cmd(
        ["git", "status", "--porcelain=v2", "--branch"],
        cwd=worktree_path,
        capture_stdout=True,
    ).stdout
    raise RuntimeError(
        "Worktree has unstaged/staged changes or an in-progress git operation; aborting.\n"
        f"worktree: {worktree_path}\n"
        "\n"
        "git status --porcelain=v2 --branch:\n"
        f"{status}"
    )


def ensure_worktree(
    *,
    repo_label: str,
    source_repo: Path,
    worktree_path: Path,
    desired_rev: str,
    base_explanation: str,
) -> None:
    if not source_repo.exists():
        raise RuntimeError(f"{repo_label} source repo does not exist: {source_repo}")
    if not git_is_repo(source_repo):
        raise RuntimeError(f"{source_repo} is not a git repository (expected {repo_label} checkout).")

    # Ensure the base commit exists in the source repo
    try:
        git_commit_exists(source_repo, desired_rev)
    except CmdError as ex:
        raise RuntimeError(
            f"The desired revision does not exist in your local {repo_label} repo.\n"
            f"  repo: {source_repo}\n"
            f"  rev:  {desired_rev}\n"
            f"  base: {base_explanation}\n"
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
                f"  repo:     {repo_label}\n"
                f"  worktree: {worktree_path}\n"
                f"  HEAD:     {head}\n"
                f"  base:     {desired_rev}\n"
                "Expected base to be an ancestor of HEAD.\n"
                "Fix by removing the worktree (git worktree remove ...) or deleting the folder, then rerun."
            )
        print(f"{repo_label}: worktree present (base OK) at HEAD {head} -> {worktree_path}")
        return

    wt_list = git_worktree_list_porcelain(source_repo)
    if str(worktree_path) in wt_list:
        raise RuntimeError(
            "Git already has a worktree registered at this path, but the directory is missing.\n"
            f"  repo: {source_repo}\n"
            f"  path: {worktree_path}\n"
            "Run: git worktree prune\n"
            "Or remove the stale worktree entry, then rerun this script."
        )

    ensure_parent_dir(worktree_path)
    cmd = ["git", "worktree", "add", "--detach", str(worktree_path), desired_rev]
    print(f"{repo_label}: creating worktree:")
    print(" ", quote_cmd(cmd))
    run_cmd(cmd, cwd=source_repo)

    head = git_head_commit(worktree_path)
    if head != desired_rev:
        raise RuntimeError(
            "Worktree creation succeeded, but HEAD doesn't match desired revision.\n"
            f"  repo:   {repo_label}\n"
            f"  HEAD:   {head}\n"
            f"  wanted: {desired_rev}\n"
        )
    print(f"{repo_label}: worktree created at {head} -> {worktree_path}")


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
    """
    polkadot-sdk base rev: from ../tanssi/Cargo.lock package 'sp-core' source.
    """
    pkgs = parse_cargo_lock_packages(lock_path)
    candidates = [p for p in pkgs if p.name == "sp-core"]

    if not candidates:
        raise RuntimeError(f"No [[package]] entry with name='sp-core' found in {lock_path}")

    def score(p: CargoLockPkg) -> int:
        s = p.source or ""
        sc = 0
        if "git+" in s:
            sc += 10
        if POLKADOT_SDK_EXPECTED_SOURCE_SUBSTR in s:
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

    if POLKADOT_SDK_EXPECTED_SOURCE_SUBSTR not in best.source:
        raise RuntimeError(
            "sp-core appears to come from an unexpected source.\n"
            f"expected to contain: {POLKADOT_SDK_EXPECTED_SOURCE_SUBSTR!r}\n"
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
    *,
    repo_label: str,
    worktree_path: Path,
    base_rev: str,
    patches_dir: Path,
) -> None:
    patches = sorted(patches_dir.glob("*.patch"))
    if not patches:
        print(f"{repo_label}: no patches found in {patches_dir}, skipping patch application.")
        return

    head = git_head_commit(worktree_path)

    if head != base_rev:
        ok, missing, total = verify_patches_applied(worktree_path, base_rev, patches_dir)
        if ok:
            print(f"{repo_label}: verified: all {total} patches already present in {base_rev}..HEAD. Skipping.")
            return

        missing_list = "\n".join(f"  - {p.name}" for p in missing[:20])
        more = "" if len(missing) <= 20 else f"\n  ... and {len(missing) - 20} more"
        raise RuntimeError(
            f"{repo_label}: worktree HEAD != base revision, and patch series does NOT appear fully applied.\n"
            f"  base: {base_rev}\n"
            f"  head: {head}\n"
            f"  patches dir: {patches_dir}\n"
            "\nMissing patches (by patch-id):\n"
            f"{missing_list}{more}\n"
            "\nRefusing to guess. Either:\n"
            "  - reset/recreate the worktree at the base revision so the script can apply patches, or\n"
            "  - export/update your patch series to match what's in the worktree."
        )

    ensure_worktree_clean_or_abort(worktree_path)

    cmd = ["git", "am", "--3way", "--keep-cr"] + [str(p) for p in patches]
    print(f"{repo_label}: applying patches:")
    print(" ", quote_cmd(cmd))
    try:
        run_cmd(cmd, cwd=worktree_path)
    except CmdError as ex:
        raise RuntimeError(
            f"{repo_label}: failed to apply patches with git am.\n"
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
    ok, missing, _total = verify_patches_applied(worktree_path, base_rev, patches_dir)
    if not ok:
        missing_list = "\n".join(f"  - {p.name}" for p in missing[:20])
        more = "" if len(missing) <= 20 else f"\n  ... and {len(missing) - 20} more"
        raise RuntimeError(
            f"{repo_label}: applied patches, but verification failed (unexpected).\n"
            f"  base: {base_rev}\n"
            f"  head: {new_head}\n"
            f"  patches dir: {patches_dir}\n"
            "\nStill missing patches (by patch-id):\n"
            f"{missing_list}{more}\n"
        )

    print(f"{repo_label}: patches applied successfully. New HEAD: {new_head}")


def run_diener_patch(*, repo_label: str, worktree_path: Path, target_repo: str) -> None:
    cmd = [
        "diener",
        "patch",
        "--crates-to-patch",
        str(worktree_path) + "/",
        "--target",
        target_repo,
    ]
    print(f"{repo_label}: running diener:")
    print(" ", quote_cmd(cmd))
    run_cmd(cmd)


def resolve_repo_root() -> Path:
    """
    Prefer git to determine the repository root (where patches/ live),
    but fall back to cwd if not in a git repo.
    """
    try:
        cp = run_cmd(["git", "rev-parse", "--show-toplevel"], capture_stdout=True)
        return Path(cp.stdout.strip()).resolve()
    except Exception:
        return Path.cwd().resolve()

_PATH_KV_RE = re.compile(r'(\bpath\s*=\s*")([^"]+)(")')

def cargo_toml_relpath(target: Path, *, manifest_dir: Path) -> Optional[str]:
    """
    Convert an absolute filesystem path to a relative path suitable for Cargo.toml,
    relative to `manifest_dir` (the directory containing that Cargo.toml).

    Returns None if a relative path cannot be computed (e.g. Windows different drive).
    """
    if not target.is_absolute():
        return target.as_posix()

    try:
        rel = os.path.relpath(str(target), start=str(manifest_dir))
    except ValueError:
        # e.g. Windows: different drive letters
        return None

    # Cargo.toml prefers forward slashes
    return Path(rel).as_posix()


def atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def relativize_worktree_paths_in_manifest(
    manifest_path: Path,
    *,
    worktree_roots: list[Path],
) -> int:
    """
    Rewrite absolute path=... entries in a single Cargo.toml to be relative,
    but only if they point inside one of `worktree_roots`.

    Returns number of replacements made.
    """
    if not manifest_path.exists():
        raise RuntimeError(f"Manifest not found: {manifest_path}")

    text = manifest_path.read_text(encoding="utf-8")
    manifest_dir = manifest_path.parent.resolve()

    # Normalize roots with trailing separator for prefix checks
    roots: list[str] = []
    for r in worktree_roots:
        rr = str(r.resolve())
        roots.append(rr)
        # also accept rr + os.sep as prefix boundary
        roots.append(rr + os.sep)

    changed = 0

    def repl(m: re.Match) -> str:
        nonlocal changed
        prefix, pstr, suffix = m.group(1), m.group(2), m.group(3)
        p = Path(pstr)

        if not p.is_absolute():
            return m.group(0)

        p_res = str(p)
        if not any(p_res.startswith(rt) for rt in roots):
            return m.group(0)

        rel = cargo_toml_relpath(p, manifest_dir=manifest_dir)
        if rel is None:
            # "if possible": keep absolute, but be loud (no silent ignoring)
            eprint(
                f"WARNING: cannot compute relative path for {pstr!r} from manifest {manifest_path} "
                "(different drive?). Keeping absolute."
            )
            return m.group(0)

        # Preserve trailing slash if present
        if pstr.endswith(("/", os.sep)) and not rel.endswith("/"):
            rel += "/"

        changed += 1
        return f"{prefix}{rel}{suffix}"

    new_text = _PATH_KV_RE.sub(repl, text)

    if changed > 0:
        atomic_write_text(manifest_path, new_text)

    return changed


def list_tracked_cargo_manifests(repo_root: Path) -> list[Path]:
    """
    Prefer `git ls-files` to avoid touching untracked/vendor files.
    Fallback: scan the repo for Cargo.toml (best-effort).
    """
    try:
        cp = run_cmd(["git", "ls-files", "Cargo.toml", "**/Cargo.toml"], cwd=repo_root, capture_stdout=True)
        paths = [repo_root / Path(p) for p in cp.stdout.splitlines() if p.strip()]
        # De-dup while preserving order
        seen: set[Path] = set()
        out: list[Path] = []
        for p in paths:
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                out.append(rp)
        return out
    except Exception:
        # Fallback scan (skip common heavy dirs)
        out: list[Path] = []
        skip = {".git", "target"}
        for p in repo_root.rglob("Cargo.toml"):
            if any(part in skip for part in p.parts):
                continue
            out.append(p.resolve())
        return out


def relativize_worktree_paths_in_repo(repo_root: Path, *, worktree_roots: list[Path]) -> None:
    manifests = list_tracked_cargo_manifests(repo_root)
    total_changed = 0
    touched: list[tuple[Path, int]] = []

    for m in manifests:
        n = relativize_worktree_paths_in_manifest(m, worktree_roots=worktree_roots)
        if n:
            total_changed += n
            touched.append((m, n))

    if total_changed == 0:
        print("Cargo.toml relativize: no absolute worktree paths found to rewrite.")
        return

    print(f"Cargo.toml relativize: rewrote {total_changed} path entries across {len(touched)} manifests:")
    for m, n in touched:
        print(f"  - {m} ({n} replacements)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create/verify worktrees for polkadot-sdk and tanssi under ../fuzz-tanssi-runtime-wt/, "
            "verify/apply local patch series for each, then run diener patch for each.\n\n"
            "tanssi base is whatever is currently checked out in the source ../tanssi repo (its HEAD)."
        )
    )

    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt; fail if inputs are missing.")
    parser.add_argument("--skip-apply-patches", action="store_true", help="Do not apply patches (still checks cleanliness).")
    parser.add_argument("--skip-diener", action="store_true", help="Do not run diener patch steps.")
    parser.add_argument(
        "--skip-relativize-cargo-paths",
        action="store_true",
        help="Do not rewrite absolute worktree path=... entries in Cargo.toml to relative paths.",
    )

    # polkadot-sdk
    parser.add_argument("--polkadot-sdk-worktree-path", default=POLKADOT_SDK_WORKTREE_DEFAULT)
    parser.add_argument("--polkadot-sdk-repo-path", default=None)
    parser.add_argument("--polkadot-sdk-patches-dir", default=POLKADOT_SDK_PATCHES_DIR_DEFAULT)
    parser.add_argument(
        "--tanssi-cargo-lock",
        default=TANSSI_LOCK_DEFAULT,
        help="Lockfile used to pin polkadot-sdk base via sp-core (default: ../tanssi/Cargo.lock)",
    )

    # tanssi
    parser.add_argument("--tanssi-worktree-path", default=TANSSI_WORKTREE_DEFAULT)
    parser.add_argument("--tanssi-repo-path", default=None)
    parser.add_argument("--tanssi-patches-dir", default=TANSSI_PATCHES_DIR_DEFAULT)

    args = parser.parse_args()

    repo_root = resolve_repo_root()

    polkadot_wt = Path(args.polkadot_sdk_worktree_path).resolve()
    tanssi_wt = Path(args.tanssi_worktree_path).resolve()

    polkadot_patches_dir = (repo_root / args.polkadot_sdk_patches_dir).resolve()
    tanssi_patches_dir = (repo_root / args.tanssi_patches_dir).resolve()

    # ---- Resolve tanssi source repo (needed for both: its HEAD, and maybe its Cargo.lock) ----
    if args.tanssi_repo_path is not None:
        tanssi_src = Path(args.tanssi_repo_path).expanduser().resolve()
    else:
        tanssi_src = (repo_root / TANSSI_REPO_DEFAULT).resolve()
        if not tanssi_src.exists() and not args.non_interactive:
            tanssi_src = prompt_for_path('Path to your "tanssi" folder', tanssi_src).resolve()
        elif not tanssi_src.exists() and args.non_interactive:
            raise RuntimeError(
                "tanssi source repo not found at default path and --non-interactive set.\n"
                f"Expected: {tanssi_src}\n"
                "Provide --tanssi-repo-path /path/to/tanssi"
            )

    if not tanssi_src.exists():
        raise RuntimeError(f"tanssi source repo does not exist: {tanssi_src}")
    if not git_is_repo(tanssi_src):
        raise RuntimeError(f"{tanssi_src} is not a git repository (expected tanssi checkout).")

    # ---- Determine base revs ----
    # polkadot-sdk base from tanssi Cargo.lock (sp-core)
    tanssi_lock = Path(args.tanssi_cargo_lock).resolve()
    polkadot_base = find_sp_core_rev(tanssi_lock)
    print(f"polkadot-sdk base (from {tanssi_lock} sp-core): {polkadot_base}")

    # tanssi base is whatever is currently checked out in the tanssi source repo
    tanssi_base = git_head_commit(tanssi_src)
    print(f"tanssi base (from {tanssi_src} HEAD): {tanssi_base}")

    # ---- Ensure polkadot-sdk worktree ----
    if not polkadot_wt.exists():
        if args.polkadot_sdk_repo_path is not None:
            polkadot_src = Path(args.polkadot_sdk_repo_path).expanduser().resolve()
        else:
            default_src = (repo_root / POLKADOT_SDK_REPO_DEFAULT).resolve()
            if args.non_interactive:
                raise RuntimeError(
                    "polkadot-sdk worktree does not exist and --polkadot-sdk-repo-path not provided "
                    "(and --non-interactive set).\n"
                    f"Missing: {polkadot_wt}\n"
                    "Provide --polkadot-sdk-repo-path /path/to/polkadot-sdk"
                )
            polkadot_src = prompt_for_path('Path to your "polkadot-sdk" folder', default_src).resolve()

        ensure_worktree(
            repo_label="polkadot-sdk",
            source_repo=polkadot_src,
            worktree_path=polkadot_wt,
            desired_rev=polkadot_base,
            base_explanation=f"{tanssi_lock} (sp-core source)",
        )
    else:
        if not git_is_repo(polkadot_wt):
            raise RuntimeError(f"polkadot-sdk worktree exists but is not a git repo: {polkadot_wt}")
        head = git_head_commit(polkadot_wt)
        if not (head == polkadot_base or git_is_ancestor(polkadot_wt, polkadot_base, "HEAD")):
            raise RuntimeError(
                "polkadot-sdk worktree does not appear to be based on the expected base.\n"
                f"  worktree: {polkadot_wt}\n"
                f"  HEAD:     {head}\n"
                f"  base:     {polkadot_base}\n"
            )
        print(f"polkadot-sdk: worktree verified (base OK) at HEAD {head} -> {polkadot_wt}")

    ensure_worktree_clean_or_abort(polkadot_wt)
    if not args.skip_apply_patches:
        apply_patches_to_worktree(
            repo_label="polkadot-sdk",
            worktree_path=polkadot_wt,
            base_rev=polkadot_base,
            patches_dir=polkadot_patches_dir,
        )
    if not args.skip_diener:
        run_diener_patch(repo_label="polkadot-sdk", worktree_path=polkadot_wt, target_repo=POLKADOT_SDK_TARGET_REPO)

    # ---- Ensure tanssi worktree ----
    if not tanssi_wt.exists():
        ensure_worktree(
            repo_label="tanssi",
            source_repo=tanssi_src,
            worktree_path=tanssi_wt,
            desired_rev=tanssi_base,
            base_explanation=f"{tanssi_src} HEAD",
        )
    else:
        if not git_is_repo(tanssi_wt):
            raise RuntimeError(f"tanssi worktree exists but is not a git repo: {tanssi_wt}")
        head = git_head_commit(tanssi_wt)
        if not (head == tanssi_base or git_is_ancestor(tanssi_wt, tanssi_base, "HEAD")):
            raise RuntimeError(
                "tanssi worktree does not appear to be based on the expected base (tanssi source HEAD).\n"
                f"  source repo: {tanssi_src}\n"
                f"  source HEAD: {tanssi_base}\n"
                f"  worktree:    {tanssi_wt}\n"
                f"  worktree HEAD:{head}\n"
                "\n"
                "Fix by removing/recreating the worktree if you intentionally moved the source repo HEAD."
            )
        print(f"tanssi: worktree verified (base OK) at HEAD {head} -> {tanssi_wt}")

    ensure_worktree_clean_or_abort(tanssi_wt)
    if not args.skip_apply_patches:
        apply_patches_to_worktree(
            repo_label="tanssi",
            worktree_path=tanssi_wt,
            base_rev=tanssi_base,
            patches_dir=tanssi_patches_dir,
        )
    if not args.skip_diener:
        run_diener_patch(repo_label="tanssi", worktree_path=tanssi_wt, target_repo=TANSSI_TARGET_REPO)

    if not args.skip_relativize_cargo_paths:
        relativize_worktree_paths_in_repo(
            repo_root,
            worktree_roots=[polkadot_wt, tanssi_wt],
        )

    print("Done.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, CmdError) as ex:
        eprint(f"ERROR: {ex}")
        raise SystemExit(2)

