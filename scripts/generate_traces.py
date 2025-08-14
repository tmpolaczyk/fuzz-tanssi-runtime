#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Tuple


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_and_capture(cmd: list[str], outfile: Path, cwd: Path | None = None) -> None:
    """
    Run a command and capture its stdout into `outfile` (no shell redirection).
    """
    ensure_dir(outfile.parent)
    with outfile.open("wb") as f:
        # TODO: ignoring warnings and build errors, print stderr on error to debug this
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, check=True, cwd=cwd)


def count_lines_bytes(path: Path) -> Tuple[int, int]:
    """
    Return (line_count, byte_count) for a file efficiently.
    """
    lines = 0
    bytes_ = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            bytes_ += len(chunk)
            lines += chunk.count(b"\n")
    return lines, bytes_


def git_is_repo(path: Path) -> bool:
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def git_commit_traces(
        repo: Path,
        subject: str,
        body_lines: list[str],
) -> None:
    """
    Stage all changes and create an (allow-empty) commit with the given message.
    """
    if not git_is_repo(repo):
        raise RuntimeError(f"{repo} is not a git repository")

    # Stage new/modified files
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

    # Build message
    msg = subject
    if body_lines:
        msg += "\n\n" + "\n".join(body_lines)

    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", msg],
        cwd=repo,
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Generate storage/event traces for a runtime & fuzz target, then commit them."
    )
    parser.add_argument(
        "--runtime",
        required=True,
        help="Runtime name (e.g., dancelight)",
    )
    parser.add_argument(
        "--fuzz-target",
        required=True,
        help="Fuzz target name (e.g., fuzz_zombie)",
    )
    parser.add_argument(
        "--traces-repo",
        default="../fuzz-tanssi-runtime-traces",
        help="Path to the traces repository (default: ../fuzz-tanssi-runtime-traces)",
    )
    parser.add_argument(
        "--cargo-profile",
        default="release",
        choices=["debug", "release"],
        help="Cargo profile to use (default: release)",
    )
    args = parser.parse_args()

    runtime = args.runtime
    fuzz_target = args.fuzz_target
    traces_repo = Path(args.traces_repo).resolve()
    cargo_profile = args.cargo_profile

    # Derived values/paths
    package = f"fuzz-{runtime}-cli"
    out_dir = traces_repo / runtime / fuzz_target
    storage_out = out_dir / "storage-trace.txt"
    event_out = out_dir / "event-trace.txt"

    # 1) Ensure directories exist
    ensure_dir(out_dir)

    # 2) Run storage-tracer
    storage_cmd = [
        "cargo",
        "run",
        "--release" if cargo_profile == "release" else "",
        "-p",
        package,
        "--",
        "storage-tracer",
        "--fuzz-target",
        fuzz_target,
    ]
    storage_cmd = [c for c in storage_cmd if c != ""]  # drop empty arg if debug
    print("Running:", " ".join(shlex.quote(x) for x in storage_cmd))
    run_and_capture(storage_cmd, storage_out)

    # 3) Run event-tracer
    event_cmd = [
        "cargo",
        "run",
        "--release" if cargo_profile == "release" else "",
        "-p",
        package,
        "--",
        "event-tracer",
        "--fuzz-target",
        fuzz_target,
    ]
    event_cmd = [c for c in event_cmd if c != ""]
    print("Running:", " ".join(shlex.quote(x) for x in event_cmd))
    run_and_capture(event_cmd, event_out)

    # 4) Prepare commit message
    now = datetime.now().astimezone()
    when_str = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    line_s, bytes_s = count_lines_bytes(storage_out)
    line_e, bytes_e = count_lines_bytes(event_out)

    invoked = f"python3 scripts/generate_traces.py --runtime {runtime} --fuzz-target {fuzz_target}"
    subject = f"traces({runtime}/{fuzz_target}): update storage+event traces"
    body = [
        f"generated: {when_str}",
        f"command:   {invoked}",
        "",
        f"storage-trace.txt: {line_s:,} lines, {bytes_s:,} bytes",
        f"event-trace.txt:   {line_e:,} lines, {bytes_e:,} bytes",
        "",
        f"package: {package}",
        f"profile: {cargo_profile}",
    ]

    # 5) Commit inside traces repo
    print(f"Committing in {traces_repo} …")
    git_commit_traces(traces_repo, subject, body)

    print("Done.")
    print(f"Storage trace -> {storage_out}")
    print(f"Event trace   -> {event_out}")


if __name__ == "__main__":
    main()
