use crate::metadata::{ACCOUNT_ID_TYPE_ID, METADATA, RUNTIME_CALL_TYPE_ID};
use crate::{ExtrOrPseudo, extrinsics_iter, extrinsics_iter_ignore_errors};
use crate::{INTERESTING_ACCOUNTS, INTERESTING_PARA_IDS, arbitrary};
use dancelight_runtime::RuntimeCall;
use itertools::{EitherOrBoth, Itertools};
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use parity_scale_codec::{Decode, Encode};
use rand::prelude::IndexedRandom;
use rand::{Rng, SeedableRng};
use scale_value::{Composite, ValueDef};
use std::io::Write;

/// Modifies input data by turning `ACCOUNT:0` into `INTERSTING_ACCOUNTS[0]`
fn mutate_interesting_accounts(data: &mut [u8]) {
    let delim_account = b"ACCOUNT:";
    let mut i = 0;

    while i < data.len() {
        let next_delimiter = data[i..]
            .windows(delim_account.len())
            .position(|window| window == delim_account);
        if next_delimiter.is_none() {
            return;
        }
        let next_delimiter = next_delimiter.unwrap();

        // start of delimiter must have at least 32 bytes after it so we can mutate it
        i += next_delimiter + 32;
        if i > data.len() {
            return;
        }

        let account_idx = data[i - 32 + delim_account.len()] as usize;
        if account_idx >= INTERESTING_ACCOUNTS.len() {
            continue;
        }

        data[i - 32..i].copy_from_slice(INTERESTING_ACCOUNTS[account_idx].as_ref());
    }
}

/// Modifies input data by turning `PARAID:0` into `INTERSTING_PARA_IDS[0]`
fn mutate_interesting_para_ids(data: &mut [u8]) {
    let delim_account = b"PARAID:";
    let mut i = 0;

    while i < data.len() {
        let next_delimiter = data[i..]
            .windows(delim_account.len())
            .position(|window| window == delim_account);
        if next_delimiter.is_none() {
            return;
        }
        let next_delimiter = next_delimiter.unwrap();

        // start of delimiter must have at least 4 bytes after it so we can mutate it
        i += next_delimiter + 4;
        if i > data.len() {
            return;
        }

        let account_idx = data[i - 4 + delim_account.len()] as usize;
        if account_idx >= INTERESTING_PARA_IDS.len() {
            continue;
        }

        data[i - 4..i].copy_from_slice(&INTERESTING_PARA_IDS[account_idx].to_le_bytes());
    }
}

#[derive(Default)]
struct SeenValues {
    account_id: Vec<scale_value::Value<u32>>,
}

fn test_mutate_value<R: Rng + ?Sized>(
    val: &mut scale_value::Value<u32>,
    seen_values: &mut SeenValues,
    rng: &mut R,
) {
    if val.context == *ACCOUNT_ID_TYPE_ID {
        seen_values.account_id.push(val.clone());

        let new_val = {
            let new = seen_values.account_id.choose(rng);
            // We pushed current value to account_id, so it cannot be empty
            new.unwrap()
        };

        // Mutate AccountId
        log::info!("Found AccountId");
        log::info!("DEBUG VAL: {:?}", val);

        *val = new_val.clone();
    }

    match &mut val.value {
        ValueDef::Composite(x) => match x {
            Composite::Named(vs) => {
                for (k, v) in vs {
                    test_mutate_value(v, seen_values, rng);
                }
            }
            Composite::Unnamed(vs) => {
                for v in vs {
                    test_mutate_value(v, seen_values, rng);
                }
            }
        },
        ValueDef::Variant(x) => match &mut x.values {
            Composite::Named(vs) => {
                for (k, v) in vs {
                    test_mutate_value(v, seen_values, rng);
                }
            }
            Composite::Unnamed(vs) => {
                for v in vs {
                    test_mutate_value(v, seen_values, rng);
                }
            }
        },
        ValueDef::BitSequence(_) => {}
        ValueDef::Primitive(_) => {}
    }
}

fn test_mutate<R: Rng + ?Sized>(
    extr: &mut [ExtrOrPseudo],
    seen_values: &mut SeenValues,
    rng: &mut R,
) {
    for extr_or_ps in extr {
        let extr = match extr_or_ps {
            ExtrOrPseudo::Extr(extr) => extr,
            ExtrOrPseudo::Pseudo(_) => continue,
        };

        //log::info!("asda EXTR: {:?}", extr);

        let mut bytes = extr.encode();
        let metadata = &*METADATA;
        let registry = &metadata.types;
        let type_id = *RUNTIME_CALL_TYPE_ID;
        //let (type_id, registry) = make_type::<Vec<ExtrOrPseudo>>();
        let mut new_value =
            match scale_value::scale::decode_as_type(&mut &*bytes, type_id, registry) {
                Ok(x) => x,
                Err(e) => {
                    //log::error!("{}", e);
                    continue;
                }
            };

        //let sss = serde_json::to_string(&new_value).unwrap();
        //log::info!("JSON EXTR: {:?}", sss);

        test_mutate_value(&mut new_value, seen_values, rng);

        // Now encode back
        let mut buf = vec![];
        // This could panic if there is a bug in scale_value crate, in that case just ignore error
        // and continue
        scale_value::scale::encode_as_type(&new_value, type_id, registry, &mut buf).unwrap();

        let new_runtime_call: RuntimeCall = RuntimeCall::decode(&mut &buf[..]).unwrap();

        *extr = new_runtime_call;
    }
}

struct CursorOutputIgnoreErrors<W>(std::io::Cursor<W>);
impl<W: std::io::Write> parity_scale_codec::Output for CursorOutputIgnoreErrors<W>
where
    std::io::Cursor<W>: std::io::Write,
{
    fn write(&mut self, bytes: &[u8]) {
        // Ignore errors
        let _ = self.0.write_all(bytes);
    }
}

// TODO: crossover and mutate operations would be more efficient if we had some delimited extrinsic
// format such as the old one. Because then we don't need to decode anything, we can reorder
// extrinsics faster.
pub fn fuzz_crossover_extr_or_pseudo(
    data1: &[u8],
    data2: &[u8],
    out: &mut [u8],
    seed: u32,
) -> usize {
    // Decode from 1
    let extr1 = extrinsics_iter(data1);
    // Decode from 2
    let extr2 = extrinsics_iter(data2);
    // Encode each item, first all from 1 then all from 2
    let mut out_writer = CursorOutputIgnoreErrors(std::io::Cursor::new(out));
    let rng = &mut rand::rngs::SmallRng::seed_from_u64(u64::from(seed));
    // 20% to keep all
    let keep_all = rng.random_ratio(20, 100);
    let mode = rng.random_range(0u8..=1);

    match mode {
        0 => {
            // Chain, first all from 1 then all from 2
            for extr in extr1.chain(extr2) {
                if !keep_all {
                    let keep_this_one = rng.random_ratio(50, 100);
                    if !keep_this_one {
                        continue;
                    }
                }
                extr.encode_to(&mut out_writer);
                if out_writer.0.position() as usize == out_writer.0.get_ref().len() {
                    break;
                }
            }
        }
        1 => {
            // Intersperse one from 1 then one from 2
            'outer: for pair in extr1.zip_longest(extr2) {
                let extrs: Vec<_> = match pair {
                    EitherOrBoth::Both(x, y) => vec![x, y],
                    EitherOrBoth::Left(x) => vec![x],
                    EitherOrBoth::Right(y) => vec![y],
                };
                for extr in extrs {
                    if !keep_all {
                        let keep_this_one = rng.random_ratio(50, 100);
                        if !keep_this_one {
                            continue;
                        }
                    }
                    extr.encode_to(&mut out_writer);
                    if out_writer.0.position() as usize == out_writer.0.get_ref().len() {
                        break 'outer;
                    }
                }
            }
        }
        _ => unreachable!(),
    }

    out_writer.0.position() as usize
}

pub fn fuzz_mutator_extr_or_pseudo(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
) -> usize {
    let mut data = data;
    let cap = data.len();
    let rng = &mut rand::rngs::SmallRng::seed_from_u64(u64::from(seed));
    let mutate_bytes = rng.random_ratio(80, 100);
    let new_size = if mutate_bytes {
        libfuzzer_sys::fuzzer_mutate(&mut data, size, cap)
    } else {
        size
    };

    // 10% to skip further mutations
    if rng.random_ratio(10, 100) {
        return new_size;
    }

    // 90% to use fast mode that processes extrinsics on the fly, without collect
    let fast_mode = rng.random_ratio(90, 100);
    if fast_mode {
        // Decode from 1
        let extr1 = extrinsics_iter(&data[..new_size]);
        let mut out = vec![0u8; max_size];
        let mut out_writer = CursorOutputIgnoreErrors(std::io::Cursor::new(out));
        let mut seen_values = SeenValues::default();

        for extr in extr1 {
            // 20% to skip each extrinsic
            let skip_this = rng.random_ratio(20, 100);
            if skip_this {
                continue;
            }

            let mut extr_v = [extr];
            extr_v[0].encode_to(&mut out_writer);
            if out_writer.0.position() as usize == out_writer.0.get_ref().len() {
                break;
            }
        }

        let new_len = out_writer.0.position() as usize;

        data[..new_len].copy_from_slice(&out_writer.0.get_ref()[..new_len]);

        new_len
    } else {
        // Slower mode
        // Decode from 1
        let mut extrs: Vec<_> = extrinsics_iter(&data[..new_size]).collect();
        if extrs.is_empty() {
            return 0;
        }

        #[derive(Arbitrary, Debug)]
        enum Op {
            Remove(u8),
            Swap(u8, u8),
            Dup(u8),
        }

        // No more ops than items
        let max_size = 2 * extrs.len();
        let arb_data_len = rng.random_range(0..=max_size);
        let arb_data: Vec<u8> = (0..arb_data_len)
            .map(|_| rng.random_range(0..extrs.len()))
            .map(|x| x as u8)
            .collect();
        let mut arb_data = Unstructured::new(&arb_data);
        let ops = <Vec<Op> as Arbitrary>::arbitrary(&mut arb_data).unwrap_or_default();

        for op in ops {
            match op {
                Op::Remove(i) => {
                    if (i as usize) < extrs.len() {
                        extrs.remove(i as usize);
                    }
                }
                Op::Swap(a, b) => {
                    if (a as usize) < extrs.len() && (b as usize) < extrs.len() {
                        extrs.swap(a as usize, b as usize);
                    }
                }
                Op::Dup(i) => {
                    if let Some(x) = extrs.get(i as usize) {
                        extrs.insert(i as usize, x.clone());
                    }
                }
            }
        }

        let mut out = vec![0u8; max_size];
        let mut out_writer = CursorOutputIgnoreErrors(std::io::Cursor::new(out));
        let mut seen_values = SeenValues::default();
        // 5% to fill extrinsics with junk
        // Probably not helpful for the fuzzer
        let add_new_ones = rng.random_ratio(5, 100);

        fn random_extrs<R: Rng + ?Sized>(rng: &mut R, attempts: usize) -> Vec<RuntimeCall> {
            let mut v = vec![];

            for _ in 0..attempts {
                let max_size = 4096;
                let rand_data_len = rng.random_range(0..=max_size);
                let rand_data: Vec<u8> = (0..rand_data_len).map(|_| rng.random()).collect();

                v.extend(extrinsics_iter_ignore_errors(&rand_data));
            }

            log::trace!(
                "Generated {} new extrs purely from fresh random data",
                v.len()
            );

            v
        }

        if extrs.is_empty() || add_new_ones {
            // Try to generate some new random extrinsics from scratch
            //extrs.extend(random_extrs(rng, 10).into_iter().map(|x| ExtrOrPseudo::Extr(x)));
        }

        for extr in extrs {
            // 20% to skip each extrinsic
            let skip_this = rng.random_ratio(20, 100);
            if skip_this {
                continue;
            }

            let mut extr_v = [extr];
            extr_v[0].encode_to(&mut out_writer);
            if out_writer.0.position() as usize == out_writer.0.get_ref().len() {
                break;
            }
        }

        let new_len = out_writer.0.position() as usize;

        data[..new_len].copy_from_slice(&out_writer.0.get_ref()[..new_len]);

        new_len
    }
}
