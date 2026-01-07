# fuzz-tanssi-runtime

## Setup

This assumes the tanssi repo is located at "../tanssi", and needs a local fork of polkadot-sdk to exist.
Use this script to setup the polkadot-sdk fork with patches that help with fuzzing

```sh
./scripts/setup_worktrees.py
```

This will create "../fuzz-tanssi-runtime-wt-polkadot-sdk", you can modify the code there directly.

## Run fuzzer

```sh
cd fuzzers/fuzz-dancelight/fuzz
SKIP_WASM_BUILD=1 cargo fuzz run fuzz_live_oneblock --build-std
```
