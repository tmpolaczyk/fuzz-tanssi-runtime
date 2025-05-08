#![no_main]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Tanssi Runtime fuzz target. Generates random extrinsics and some pseudo-extrinsics.
//!
//! Based on https://github.com/srlabs/substrate-runtime-fuzzer/blob/2a42a8b750aff0e12eb0e09b33aea9825a40595a/runtimes/kusama/src/main.rs

use {
    dancelight_runtime::RuntimeCall,
    parity_scale_codec::{Decode, DecodeLimit, Encode},
    std::{cmp::min, iter},
};

#[derive(Debug, Encode, Decode)]
enum FuzzRuntimeCall {
    // Intentionally empty, we only want real runtime calls in this fuzzer
    // while keeping compatibility with other fuzzers that do use custom calls
}

#[derive(Debug, Encode, Decode)]
enum ExtrOrPseudo {
    Extr(RuntimeCall),
    Pseudo(FuzzRuntimeCall),
}

fn init_logger() {
    use sc_tracing::logging::LoggerBuilder;
    let env_rust_log = std::env::var("RUST_LOG");
    // No logs by default
    let mut logger = LoggerBuilder::new(env_rust_log.unwrap_or("".to_string()));
    logger.with_log_reloading(false).with_detailed_output(false);

    logger.init().unwrap();
}

lazy_static::lazy_static! {
    static ref LOGGER: () = init_logger();
}

fn extrinsics_iter(mut extrinsic_data: &[u8]) -> impl Iterator<Item = ExtrOrPseudo> + use<'_> {
    iter::from_fn(move || DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
}

/// Wrap [`extrinsics_iter`] but only decode the first item.
/// This limits the fuzzer to 1 extrinsic per corpus file, while still keeping the Vec<Extr> format
/// in corpus files.
fn one_extrinsic_iter(extrinsic_data: &[u8]) -> impl Iterator<Item = ExtrOrPseudo> + use<'_> {
    extrinsics_iter(extrinsic_data).take(1)
}

fn fuzz_main(data: &[u8]) {
    //println!("data: {:?}", data);
    let num_extrinsics = one_extrinsic_iter(data).count();
    assert!(num_extrinsics <= 1);
}

fn fuzz_init() {
    // Uncomment to init logger
    init_logger();
}

libfuzzer_sys::fuzz_target!(init: fuzz_init(), |data: &[u8]| fuzz_main(data));
