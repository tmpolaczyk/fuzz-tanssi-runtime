# fuzz-tanssi-runtime

## Setup

```sh
cargo install cargo-fuzz
```

### Worktrees

This program assumes the tanssi repo is located at "../tanssi", and needs a local fork of polkadot-sdk to exist.
Use this script to setup the polkadot-sdk fork with patches that help with fuzzing

```sh
./scripts/setup_worktrees.py
```

This will create "../fuzz-tanssi-runtime-wt/polkadot-sdk" and "../fuzz-tanssi-runtime-wt/tanssi", you can modify the code there directly.

### Snapshots

The fuzzer needs some snapshots of the live network storage at compile time. These are a few MB and change constantly, so they are not included in this git repo.
See `docs/snapshots.md` for instructions on how to generate them.

## Run fuzzer

```sh
cd fuzzers/fuzz-dancelight/fuzz
SKIP_WASM_BUILD=1 cargo fuzz run fuzz_live_oneblock --build-std
```

## Helper utilities

```sh
# Generate list of storage read/writes, events emitted and extrinsics called
./scripts/generate_traces.py --runtime dancelight --fuzz-target fuzz_zombie
# Generate code coverage as html files
./scripts/run_coverage.py --fuzz-target fuzz_zombie --runtime dancelight
```
