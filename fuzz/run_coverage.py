#!/usr/bin/env python3

def merge_rust_files_optimized(file1, file2, output_file):
    # Define the header based on the file names
    header = [
        f"//! Generate coverage for the `fuzz_raw` target.\n",
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
            file1_contents[i] = 'const FUZZ_TARGET_NAME: &str = "fuzz_raw";\n'
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

    with open(output_file, 'w') as f:
        f.writelines(final_content)

# Example usage
merge_rust_files_optimized('fuzz_targets/coverage.rs', 'fuzz_targets/fuzz_raw.rs', 'fuzz_targets/fuzz_raw_coverage.rs')
