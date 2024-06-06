#![no_main]

//! Check if XCM updates cause breaking changes to encoding.
//! Tries to decode raw bytes as XCM v3 and also as XCM v4, and compares the result.
//! If it is not identical, panics.

use parity_scale_codec::{Decode, DecodeLimit, Encode};

fn init_logger() {
    use sc_tracing::logging::LoggerBuilder;
    let mut logger = LoggerBuilder::new(format!("error"));
    logger.with_log_reloading(false).with_detailed_output(false);

    logger.init().unwrap();
}

lazy_static::lazy_static! {
    static ref LOGGER: () = init_logger();
}

fn fuzz_main(data: &[u8]) {
    let mut d = data;
    let multilocation_v3 = staging_xcm::v3::MultiLocation::decode(&mut d);
    let mut d = data;
    let multilocation_v4 = staging_xcm::v4::Location::decode(&mut d);

    match (multilocation_v3, multilocation_v4) {
        (Err(_), Err(_)) => return,
        (Ok(v3), Ok(v4)) => {
            let v3_to_v4: staging_xcm::v4::Location = v3.try_into().unwrap();
            assert_eq!(v3_to_v4, v4);
        }
        r => panic!("{:?}", r),
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| { fuzz_main(data) });
