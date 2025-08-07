#![no_main]

//! Tanssi Runtime fuzz target. Decodes runtime calls from bytes, trying to achieve max coverage.

use fuzz_dancelight::*;

/// Wrap [`extrinsics_iter`] but only decode the first item.
/// This limits the fuzzer to 1 extrinsic per corpus file, while still keeping the Vec<Extr> format
/// in corpus files.
/// Note that since we ignore trailing bytes, it is possible that the remaining bytes also decode to
/// valid extrinsics. So it cannot be assumed that the corpus files all have only 1 extrinsic each.
/// But only the first extrinsic affects the coverage of this fuzzer.
fn one_extrinsic_iter(extrinsic_data: &[u8]) -> impl Iterator<Item = ()> + use<'_> {
    extrinsics_iter_only_runtime_calls(extrinsic_data)
        .map(drop)
        .take(1)
}

fn fuzz_init() {
    init_logger();
}

fn fuzz_main(data: &[u8]) {
    //println!("data: {:?}", data);
    let num_extrinsics = one_extrinsic_iter(data).count();
    assert!(num_extrinsics <= 1);
}

libfuzzer_sys::fuzz_target!(init: fuzz_init(), |data: &[u8]| fuzz_main(data));

/*
libfuzzer_sys::fuzz_crossover!(|data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32| {
    fuzz_crossover_extr_or_pseudo(data1, data2, out, seed)
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    fuzz_mutator_extr_or_pseudo(data, size, max_size, seed)
});
*/
