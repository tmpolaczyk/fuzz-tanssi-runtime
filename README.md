# Setup

Install requirements

```
cargo install cargo-fuzz
```

Make sure you clone this repo right next to the tanssi folder (`cd ../tanssi` should work)

```
git clone https://github.com/tmpolaczyk/fuzz-tanssi-runtime
cd fuzz-tanssi-runtime
```

# Run

```
cargo fuzz run fuzz_raw
# Or using 8 threads
cargo fuzz run fuzz_raw -j8
```

Uncomment the `println!` calls for a more verbose output.

# Coverage v3

Run all these commands from inside "fuzz" folder:

Optionally, remove old coverage runs from `proffiles` folder.

Modify `target_name` in `run_coverage.py`

Run it

```
rustup component add llvm-tools-preview
grcov proffiles/ -s $HOME --binary-path ./target/x86_64-unknown-linux-gnu/debug -t html --branch --ignore-not-existing --ignore "target/debug/build/*" --ignore "*mock.rs" --ignore "*tests.rs"             -o coverage --llvm
```

Will put coverage from `proffiles/*` into `coverage` folder.

Open `coverage/index.html` to see it.

To upload the coverage to github pages:

```
git checkout gh-pages
cp -rf fuzz/coverage_tmpname coverage/{target_name}
# update index.html if new target
git add coverage
git commit -a --amend
git push -f
git checkout -
```

# Profiling

You can run perf on the fuzzer binary as is.

Delete the corpus if you want to see performance with an empty corpus, or keep the corpus to see performance when processing the corpus.

```
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
# Copy the fuzzer command here, it is printed when running cargo fuzz
perf record --call-graph=dwarf target/x86_64-unknown-linux-gnu/release/fuzz_starlight_live_oneblock_events -artifact_prefix=/home/tomasz/projects/fuzz-tanssi-runtime/fuzz/artifacts/fuzz_starlight_live_oneblock_events /home/tomasz/projects/fuzz-tanssi-runtime/fuzz/corpus/fuzz_starlight_live_oneblock_events
perf script | inferno-collapse-perf > stacks.folded
cat stacks.folded | inferno-flamegraph > flamegraph.svg
# open in a web browser flamegraph.svg
```
