#![no_main]

use fuzz_dancelight::*;

libfuzzer_sys::fuzz_target!(init: fuzz_init::<FuzzZombie>(), |data: &[u8]| fuzz_zombie::<FuzzZombie>(data));

libfuzzer_sys::fuzz_crossover!(|data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32| {
    fuzz_crossover_extr_or_pseudo(data1, data2, out, seed)
});

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    fuzz_mutator_extr_or_pseudo(data, size, max_size, seed)
});
