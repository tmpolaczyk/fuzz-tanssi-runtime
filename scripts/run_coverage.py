#!/usr/bin/env python3
import argparse
import os
import subprocess
import shutil
from datetime import datetime

def build_coverage_binary(runtime_name):
    """
    Builds the coverage binary by running a cargo run command with specific RUSTFLAGS.
    """
    env = os.environ.copy()
    env["RUSTFLAGS"] = "--cfg fuzzing --cfg coverage -C opt-level=3 -C target-cpu=native -C instrument-coverage"
    #env["RUSTFLAGS"] = "--cfg fuzzing --cfg coverage -C opt-level=3 -C target-cpu=native"
    #env["RUSTFLAGS"] = "--cfg fuzzing --cfg coverage -C opt-level=3"
    env["LLVM_PROFILE_FILE"] = "/dev/null"
    #subprocess.run(["cargo", "build", "-Z", "build-std", "--target", "x86_64-unknown-linux-gnu", "--bin", f"{target_name}_coverage"], env=env, check=True)
    # -Z build-std is not compatible with -C instrument-coverage
    # cargo run --release -p fuzz-dancelight-cli -- execute-corpus --fuzz-target fuzz_live_oneblock
    subprocess.run(["cargo", "build", "-p", f"fuzz-{runtime_name}-cli"], env=env, check=True)
    #env["RUSTFLAGS"] = "--cfg fuzzing"
    #subprocess.run(["cargo", "miri", "run", "--bin", f"{target_name}_coverage"], env=env, check=True)

def rm_rf_contents(path):
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)
def execute_coverage_binary(runtime_name, target_name):
    """
    Executes the 'fuzz_raw_coverage' binary located in the 'target/debug' directory.
    """
    try:
        # remove old proffiles
        rm_rf_contents("proffiles")
        env = os.environ.copy()
        # TODO: use absolute path
        env["LLVM_PROFILE_FILE"] = "proffiles/default_%m_%p.profraw"
        env["RUST_LOG"] = "off"
        bin_name = f"fuzz-{runtime_name}-cli"
        # cargo run --release -p fuzz-dancelight-cli -- execute-corpus --fuzz-target fuzz_live_oneblock
        subprocess.run([f"./target/debug/{bin_name}", "execute-corpus", "--fuzz-target", target_name], env=env, check=True)
    except Exception as e:
        print(f"Failed to execute '{target_name}': {e}")

def generate_html_report(runtime_name):
    base_dir = "coverage"
    latest_dir = os.path.join(base_dir, "latest")
    output_path = os.path.join(latest_dir, "html")

    # Ensure base coverage directory exists
    os.makedirs(base_dir, exist_ok=True)

    # If coverage/latest exists, move it to a timestamped backup (never delete)
    if os.path.exists(latest_dir):
        # The timestamp depends on folder original creation time
        try:
            ctime = os.path.getctime(latest_dir)
        except OSError:
            # Fallback: modification time if creation time not available
            ctime = os.path.getmtime(latest_dir)
        ts = datetime.fromtimestamp(ctime).strftime("%Y%m%d-%H%M%S")
        backup_dir = os.path.join(base_dir, f"backup-{ts}")
        # Guarantee uniqueness just in case
        suffix = 1
        while os.path.exists(backup_dir):
            backup_dir = os.path.join(base_dir, f"backup-{ts}-{suffix}")
            suffix += 1
        shutil.move(latest_dir, backup_dir)
        print(f"Moved existing '{latest_dir}' to '{backup_dir}'")

    # Recreate latest output directory
    os.makedirs(output_path, exist_ok=True)

    bin_name = f"fuzz-{runtime_name}-cli"
    bin_path = f"./target/debug/{bin_name}"

    os.makedirs(output_path, exist_ok=True)
    profdata_path = os.path.join(base_dir, "coverage.profdata")

    # Merge all raw profiles into a single .profdata
    subprocess.run(
        ["cargo-profdata", "--", "merge", "--sparse", "proffiles/", "-o", profdata_path],
        check=True,
    )

    # Generate HTML report
    subprocess.run(
        [
            "cargo-cov", "--", "show", bin_path,
            f"--instr-profile={profdata_path}",
            "--format=html",
            "--output-dir", output_path,
            "--show-branches=count",
            "--show-line-counts-or-regions",
            "--show-expansions",
            "--show-mcdc",
        ],
        check=True,
    )

    print(f"HTML coverage report generated at {os.path.join(output_path, 'index.html')}")
    return

def upload_to_ghpages(runtime_name):
    return
    # Unimplemented, need to run this command manually:
    """
    git checkout gh-pages
    cp -rf fuzz/coverage_tmpname coverage/{target_name}
    # update index.html if new target
    git add coverage
    git commit -a --amend
    git push -f
    git checkout -
    """

def main():
    parser = argparse.ArgumentParser(description="Build, run fuzz coverage, and generate HTML report.")
    parser.add_argument("--fuzz-target", required=True, help="Fuzz target name (e.g., fuzz_live_oneblock)")
    parser.add_argument("--runtime", required=True, help="Runtime name (e.g., dancelight)")
    args = parser.parse_args()

    target_name = args.fuzz_target
    runtime_name = args.runtime

    build_coverage_binary(runtime_name)
    execute_coverage_binary(runtime_name, target_name)
    generate_html_report(runtime_name)
    upload_to_ghpages(runtime_name)

if __name__ == "__main__":
    main()

