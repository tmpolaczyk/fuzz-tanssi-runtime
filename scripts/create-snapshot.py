#!/usr/bin/env python3
"""
Automate Substrate snapshot creation, conversion, merging, and fuzz-target export
All outputs are stored in a 'snapshots' directory; only final JSON specs are kept.
"""
import argparse
import subprocess
import shutil
from pathlib import Path
import sys

def run(cmd, **kwargs):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)

def main():
    parser = argparse.ArgumentParser(
        description="Automate snapshot workflow for Substrate chain specs"
    )
    parser.add_argument("--uri", required=True, help="Websocket URI of the node")
    parser.add_argument("--runtime", required=True, help="Runtime identifier, starlight or dancelight")
    parser.add_argument(
        "--output",
        required=True,
        help="Basename for the output JSON (without path or extension)",
    )
    args = parser.parse_args()

    # Determine directories
    script_dir = Path(__file__).resolve().parent
    snapshots_dir = script_dir.parent / "snapshots"
    snapshots_dir.mkdir(exist_ok=True)

    base_name = args.output.rstrip(".json")
    snapshot_file = snapshots_dir / f"{base_name}.snap"
    hex_snapshot = snapshots_dir / f"{base_name}.hexsnap.txt"
    output_json = snapshots_dir / f"{base_name}.json"
    before_init_json = snapshots_dir / f"{base_name}-before-oninitialize.json"
    fuzz_output = snapshots_dir / f"fuzz_{args.runtime}_live_export_state.hexsnap.txt"
    empty_json = snapshots_dir / "empty-chain-spec.json"

    # 1. Create raw snapshot
    run(["snap2zombie", "create-snapshot", "--uri", args.uri, str(snapshot_file)])

    # 2. Convert snapshot to hex
    run([
        "snap2zombie",
        "to-hex-snap",
        "--snapshot-path",
        str(snapshot_file),
        "--output-path",
        str(hex_snapshot),
    ])

    # 3. Initialize chain spec JSON
    print(f"[*] Copying empty chain spec to: {output_json}")
    shutil.copy(empty_json, output_json)

    # 4. Merge hex snapshot into chain spec
    run([
        "snap2zombie",
        "merge-into-raw",
        "--chain-spec-path",
        str(output_json),
        "--hex-snapshot-path",
        str(hex_snapshot),
        "--all",
    ])

    # 5. Save pre-on_initialize state
    print(f"[*] Saving pre-on_initialize chain spec: {before_init_json}")
    shutil.copy(output_json, before_init_json)

    # 6. Run fuzz export for on_initialize state
    run([
        "cargo",
        "run",
        "--release",
        "-p",
        f"fuzz-{args.runtime}-cli",
        "--",
        "update-snapshot",
        "--input-snapshot-path",
        str(before_init_json),
        "--output-hexsnapshot-path",
        str(fuzz_output),
    ])

    # 7. Merge fuzz-exported state into chain spec
    run([
        "snap2zombie",
        "merge-into-raw",
        "--chain-spec-path",
        str(output_json),
        "--hex-snapshot-path",
        str(fuzz_output),
        "--all",
    ])

    # 8. Cleanup intermediate files
    print("[*] Cleaning up intermediate files")
    for path in (snapshot_file, hex_snapshot, fuzz_output):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    print(f"\nCompleted! Kept files in '{snapshots_dir}':")
    print(f"  - Final chain spec JSON:    {output_json.name}")
    print(f"  - Pre-on_initialize JSON:    {before_init_json.name}")

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"Error: Command '{' '.join(e.cmd)}' exited with status {e.returncode}", file=sys.stderr)
        sys.exit(e.returncode)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
