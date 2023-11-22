#!/usr/bin/env python3
import os
import subprocess

def setup_coverage_target(target_name):
    """
    Sets up the coverage target by running a cargo fuzz command.
    Ignores failures and suppresses all output.
    """
    target_coverage_name = f"{target_name}_coverage"
    subprocess.run(
        ["cargo", "fuzz", "add", target_coverage_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def write_coverage_target(target_name, file1, file2, output_file):
    """
    Merges two Rust files into a new file with specific modifications.
    """
    # Define the header based on the file names
    header = [
        f"//! Generate coverage for the `{target_name}` target.\n",
        f"//! Warning: this file has been automatically generated using the `run_coverage.py` script\n",
        f"//! from the contents of `{file1}` and `{file2}`.\n",
        "\n"
    ]

    # Read and modify the contents of the first file
    with open(file1, 'r') as f:
        file1_contents = f.readlines()

    for i, line in enumerate(file1_contents):
        stripped_line = line.strip()
        if stripped_line.startswith("const FUZZ_TARGET_NAME: &str"):
            file1_contents[i] = f'const FUZZ_TARGET_NAME: &str = "{target_name}";\n'
            break

    # Read and modify the contents of the second file
    with open(file2, 'r') as f:
        file2_contents = f.readlines()

    file2_contents_cleaned = ["\n// fuzz_raw.rs"]
    for line in file2_contents:
        stripped_line = line.strip()
        if stripped_line.startswith("libfuzzer_sys::fuzz_target!"):
            break
        if not stripped_line.startswith("//!") and stripped_line != "#![no_main]":
            file2_contents_cleaned.append(line)

    # Merge the contents with the header, remove the last newline, and write to the output file
    final_content = header + file1_contents + file2_contents_cleaned
    if final_content[-1] == "\n":
        final_content.pop()

    # Combine all lines in final_content into a single string
    final_content_join = "".join(final_content)

    # Check if the output file already has this content
    # This avoids triggering a useless cargo build
    try:
        with open(output_file, 'r') as f:
            existing_content_join = f.read()

        # Using difflib to find differences
        if existing_content_join == final_content_join:
            return  # No need to write if the content is the same
    except FileNotFoundError:
        print(f"{output_file} not found. A new file will be created.")

    # Write to the output file
    with open(output_file, 'w') as f:
        f.write(final_content_join)
        print(f"Updated {output_file}")

def build_coverage_binary(target_name):
    """
    Builds the coverage binary by running a cargo run command with specific RUSTFLAGS.
    """
    env = os.environ.copy()
    env["RUSTFLAGS"] = "--cfg fuzzing --cfg coverage -C opt-level=3 -C target-cpu=native -C instrument-coverage"
    env["LLVM_PROFILE_FILE"] = "/dev/null"
    subprocess.run(["cargo", "build", "--bin", f"{target_name}_coverage"], env=env)

def execute_coverage_binary(target_name):
    """
    Executes the 'fuzz_raw_coverage' binary located in the 'target/debug' directory.
    """
    try:
        env = os.environ.copy()
        # TODO: use absolute path
        env["LLVM_PROFILE_FILE"] = "proffiles/default_%m_%p.profraw"
        subprocess.run([f"./target/debug/{target_name}_coverage"])
    except Exception as e:
        print(f"Failed to execute '{target_name}_coverage': {e}")

def main():
    target_name = "fuzz_raw"
    setup_coverage_target(target_name)
    write_coverage_target(target_name, 'fuzz_targets/coverage.rs', f"fuzz_targets/{target_name}.rs", f"fuzz_targets/{target_name}_coverage.rs")
    build_coverage_binary(target_name)
    execute_coverage_binary(target_name)

if __name__ == "__main__":
    main()

