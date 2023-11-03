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

# Coverage

```
cd fuzz
cargo fuzz coverage fuzz_raw
$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_raw     --format=html     -instr-profile=coverage/fuzz_raw/coverage.profdata  --ignore-filename-regex='.*/\.cargo/.*'   > index.html
firefox index.html
```
