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
from datetime import date

PRESETS = {
    "stagelight": {
        "uri": "wss://services.tanssi-dev.network/stagelight",
        "runtime": "dancelight",
    },
    "dancelight": {
        "uri": "wss://dancelight.tanssi-api.network",
        "runtime": "dancelight",
    },
    "moonlight": {
        "uri": "wss://services.tanssi-dev.network/moonlight",
        "runtime": "starlight",
    },
    "starlight": {
        "uri": "wss://tanssi.tanssi-mainnet.network",
        "runtime": "starlight",
    },
}


def run(cmd, **kwargs):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(
        description="Automate snapshot workflow for Substrate chain specs"
    )

    # mutually-exclusive: either alias OR manual trio
    parser.add_argument(
        "--alias",
        choices=PRESETS.keys(),
        help="Use one of the preset configs to set uri, runtime & output",
    )
    parser.add_argument("--uri", help="Websocket URI of the node")
    parser.add_argument("--runtime", help="Runtime identifier, starlight or dancelight")
    parser.add_argument(
        "--output",
        help="Basename for the output JSON (without path or extension)",
    )

    args = parser.parse_args()

    # resolve presets vs manual
    if args.alias:
        cfg = PRESETS[args.alias]
        args.uri = cfg["uri"]
        args.runtime = cfg["runtime"]
        today = date.today()
        output_path = f"{args.alias}-{today:%Y-%m-%d}.json"
        args.output = output_path
    else:
        # enforce manual when no alias
        if not (args.uri and args.runtime and args.output):
            parser.error(
                "You must specify either --alias ALIAS "
                "or all of --uri, --runtime and --output"
            )

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

    # --- abort early if the chosen output already exists ---
    if output_json.exists():
        print(f"Error: output file '{output_json}' already exists.", file=sys.stderr)
        sys.exit(1)

    # 1. Create raw snapshot
    run(["snap2zombie", "create-snapshot", "--uri", args.uri, str(snapshot_file)])

    # 2. Convert snapshot to hex
    run(
        [
            "snap2zombie",
            "to-hex-snap",
            "--snapshot-path",
            str(snapshot_file),
            "--output-path",
            str(hex_snapshot),
        ]
    )

    # 3. Initialize chain spec JSON
    print(f"[*] Copying empty chain spec to: {output_json}")
    shutil.copy(empty_json, output_json)

    # 4. Merge hex snapshot into chain spec
    run(
        [
            "snap2zombie",
            "merge-into-raw",
            "--chain-spec-path",
            str(output_json),
            "--hex-snapshot-path",
            str(hex_snapshot),
            "--all",
        ]
    )

    # 5. Save pre-on_initialize state
    print(f"[*] Saving pre-on_initialize chain spec: {before_init_json}")
    shutil.copy(output_json, before_init_json)

    # 6. Run fuzz export for on_initialize state
    run(
        [
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
        ]
    )

    # 7. Merge fuzz-exported state into chain spec
    run(
        [
            "snap2zombie",
            "merge-into-raw",
            "--chain-spec-path",
            str(output_json),
            "--hex-snapshot-path",
            str(fuzz_output),
            "--all",
        ]
    )

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
        print(
            f"Error: Command '{' '.join(e.cmd)}' exited with status {e.returncode}",
            file=sys.stderr,
        )
        sys.exit(e.returncode)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
