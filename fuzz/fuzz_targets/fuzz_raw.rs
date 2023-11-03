#![no_main]

//! Tanssi Runtime fuzz target. Generates random extrinsics and some mock relay validation data (but no sudo).
//! 
//! Based on https://github.com/srlabs/substrate-runtime-fuzzer/blob/8d45d9960cff6f6c5aa8bf19808f84ef12b08535/node-template-fuzzer/src/main.rs

use {
    cumulus_primitives_core::ParaId,
    dancebox_runtime::{
        AccountId, AllPalletsWithSystem, BlockNumber, Executive, Runtime, RuntimeCall,
        RuntimeOrigin, Signature, UncheckedExtrinsic, SLOT_DURATION,
    },
    frame_support::{
        dispatch::GetDispatchInfo,
        pallet_prelude::Weight,
        traits::{IntegrityTest, TryState, TryStateSelect},
        weights::constants::WEIGHT_REF_TIME_PER_SECOND,
    },
    nimbus_primitives::NimbusId,
    parity_scale_codec::{DecodeLimit, Encode},
    sp_consensus_aura::{Slot, AURA_ENGINE_ID},
    sp_core::{sr25519, Decode, Get, Pair, Public},
    sp_inherents::InherentDataProvider,
    sp_runtime::{
        traits::{Dispatchable, Header, IdentifyAccount, Verify},
        Digest, DigestItem, Storage,
    },
    std::time::{Duration, Instant},
    tp_container_chain_genesis_data::ContainerChainGenesisData,
};

// We use a simple Map-based Externalities implementation
type Externalities = sp_state_machine::BasicExternalities;

// The initial timestamp at the start of an input run.
const INITIAL_TIMESTAMP: u64 = 0;

/// The maximum number of blocks per fuzzer input.
/// If set to 0, then there is no limit at all.
/// Feel free to set this to a low number (e.g. 4) when you begin your fuzzing campaign and then set it back to 32 once you have good coverage.
const MAX_BLOCKS_PER_INPUT: usize = 32;

/// The maximum number of extrinsics per block.
/// If set to 0, then there is no limit at all.
/// Feel free to set this to a low number (e.g. 4) when you begin your fuzzing campaign and then set it back to 0 once you have good coverage.
const MAX_EXTRINSICS_PER_BLOCK: usize = 0;

/// Max number of seconds a block should run for.
const MAX_TIME_FOR_BLOCK: u64 = 6;

// We do not skip more than DEFAULT_STORAGE_PERIOD to avoid pallet_transaction_storage from
// panicking on finalize.
const MAX_BLOCK_LAPSE: u32 = sp_transaction_storage_proof::DEFAULT_STORAGE_PERIOD;

// Extrinsic delimiter: `********`
const DELIMITER: [u8; 8] = [42; 8];

struct Data<'a> {
    data: &'a [u8],
    pointer: usize,
    size: usize,
}

impl<'a> Data<'a> {
    fn size_limit_reached(&self) -> bool {
        !(MAX_BLOCKS_PER_INPUT == 0 || MAX_EXTRINSICS_PER_BLOCK == 0)
            && self.size >= MAX_BLOCKS_PER_INPUT * MAX_EXTRINSICS_PER_BLOCK
    }
}

impl<'a> Iterator for Data<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() <= self.pointer || self.size_limit_reached() {
            return None;
        }
        let next_delimiter = self.data[self.pointer..]
            .windows(DELIMITER.len())
            .position(|window| window == DELIMITER);
        let next_pointer = match next_delimiter {
            Some(delimiter) => self.pointer + delimiter,
            None => self.data.len(),
        };
        let res = Some(&self.data[self.pointer..next_pointer]);
        self.pointer = next_pointer + DELIMITER.len();
        self.size += 1;
        res
    }
}

// Relay data delimiter (one asterisc less than extrinsic delimiter): `*******`
const RELAY_DELIMITER: [u8; 7] = [42; 7];

struct RelayData<'a> {
    data: &'a [u8],
    pointer: usize,
    size: usize,
}

impl<'a> RelayData<'a> {
    fn size_limit_reached(&self) -> bool {
        false
    }
}

impl<'a> Iterator for RelayData<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() <= self.pointer || self.size_limit_reached() {
            return None;
        }
        let next_delimiter = self.data[self.pointer..]
            .windows(RELAY_DELIMITER.len())
            .position(|window| window == RELAY_DELIMITER);
        let next_pointer = match next_delimiter {
            Some(delimiter) => self.pointer + delimiter,
            None => self.data.len(),
        };
        let res = Some(&self.data[self.pointer..next_pointer]);
        self.pointer = next_pointer + RELAY_DELIMITER.len();
        self.size += 1;
        res
    }
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

pub fn mock_container_chain_genesis_data<MaxLengthTokenSymbol: Get<u32>>(
    para_id: ParaId,
) -> ContainerChainGenesisData<MaxLengthTokenSymbol> {
    ContainerChainGenesisData {
        storage: vec![],
        name: format!("Container Chain {}", para_id).into(),
        id: format!("container-chain-{}", para_id).into(),
        fork_id: None,
        extensions: vec![],
        properties: Default::default(),
    }
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate collator keys from seed.
///
/// This function's return type must always match the session keys of the chain in tuple format.
pub fn get_collator_keys_from_seed(seed: &str) -> NimbusId {
    get_from_seed::<NimbusId>(seed)
}

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate the session keys from individual elements.
///
/// The input must be a tuple of individual keys (a single arg for now since we have just one key).
pub fn template_session_keys(keys: NimbusId) -> dancebox_runtime::SessionKeys {
    dancebox_runtime::SessionKeys { nimbus: keys }
}

/// Helper function to turn a list of names into a list of `(AccountId, NimbusId)`
pub fn invulnerables_from_seeds<S: AsRef<str>, I: Iterator<Item = S>>(
    names: I,
) -> Vec<(AccountId, NimbusId)> {
    names
        .map(|name| {
            let name = name.as_ref();
            (
                get_account_id_from_seed::<sr25519::Public>(name),
                get_collator_keys_from_seed(name),
            )
        })
        .collect()
}

/// Helper function to turn a list of names into a list of `AccountId`
pub fn account_ids(names: &[&str]) -> Vec<AccountId> {
    names
        .iter()
        .map(|name| get_account_id_from_seed::<sr25519::Public>(name))
        .collect()
}

lazy_static::lazy_static! {
    static ref GENESIS_STORAGE: Storage = {
        let endowed_accounts: Vec<AccountId> = (0..5).map(|i| [i; 32].into()).collect();

        let genesis_storage: Storage = {
            use sp_runtime::BuildStorage;
            use tp_container_chain_genesis_data::json::container_chain_genesis_data_from_path;
            use dancebox_runtime::prod_or_fast;
            use cumulus_primitives_core::ParaId;

            let container_chains: Vec<&str> = vec![];
            let mock_container_chains: Vec<ParaId> = vec![2000.into(), 2001.into()];
            let invulnerables = vec![
                    "Alice".to_string(),
                    "Bob".to_string(),
                    "Charlie".to_string(),
                    "Dave".to_string(),
            ];
            let invulnerables = invulnerables_from_seeds(invulnerables.iter());

            dancebox_runtime::RuntimeGenesisConfig {
                system: dancebox_runtime::SystemConfig {
                    code: dancebox_runtime::WASM_BINARY
                        .expect("WASM binary was not build, please build it!")
                        .to_vec(),
                    ..Default::default()
                },
                balances: dancebox_runtime::BalancesConfig {
                    balances: endowed_accounts
                        .iter()
                        .cloned()
                        .map(|k| (k, 1 << 60))
                        .collect(),
                },
                parachain_info: dancebox_runtime::ParachainInfoConfig {
                    parachain_id: 1000.into(),
                    ..Default::default()
                },
                invulnerables: dancebox_runtime::InvulnerablesConfig {
                    invulnerables: invulnerables.iter().cloned().map(|(acc, _)| acc).collect(),
                },
                session: dancebox_runtime::SessionConfig {
                    keys: invulnerables
                        .into_iter()
                        .map(|(acc, aura)| {
                            (
                                acc.clone(),                 // account id
                                acc,                         // validator id
                                template_session_keys(aura), // session keys
                            )
                        })
                        .collect(),
                },
                parachain_system: Default::default(),
                configuration: dancebox_runtime::ConfigurationConfig {
                        config: pallet_configuration::HostConfiguration {
                            max_collators: 100u32,
                            min_orchestrator_collators: 1u32,
                            max_orchestrator_collators: 1u32,
                            collators_per_container: 2u32,
                            full_rotation_period: prod_or_fast!(24u32, 5u32),
                        },
                        ..Default::default()
                },
                registrar: dancebox_runtime::RegistrarConfig {
                    para_ids: container_chains
                        .iter()
                        .map(|x| {
                            container_chain_genesis_data_from_path(x).unwrap_or_else(|e| {
                                panic!(
                                    "Failed to build genesis data for container chain {:?}: {}",
                                    x, e
                                )
                            })
                        })
                        .chain(
                            mock_container_chains
                                .iter()
                                .map(|x| (*x, mock_container_chain_genesis_data(*x), vec![])),
                        )
                        .collect(),
                },
                sudo: dancebox_runtime::SudoConfig {
                    key: None,
                },
                migrations: dancebox_runtime::MigrationsConfig {
                    ..Default::default()
                },
                maintenance_mode: dancebox_runtime::MaintenanceModeConfig {
                    start_in_maintenance_mode: false,
                    ..Default::default()
                },
                // This should initialize it to whatever we have set in the pallet
                polkadot_xcm: dancebox_runtime::PolkadotXcmConfig::default(),
                transaction_payment: Default::default(),
            }
            .build_storage()
            .unwrap()
        };

        genesis_storage
    };
}

fn fuzz_main(data: &[u8]) {
    let endowed_accounts: Vec<AccountId> = (0..5).map(|i| [i; 32].into()).collect();
    {
        let iteratable = Data {
            data,
            pointer: 0,
            size: 0,
        };

        // Max weight for a block.
        let max_weight: Weight = Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND * 2, 0);

        let mut block_count = 0;
        let mut extrinsics_in_block = 0;
        let mut mock_relay_bytes: Vec<Vec<u8>> = vec![];

        let extrinsics: Vec<(Option<u32>, usize, RuntimeCall)> = iteratable
            .filter_map(|data| {
                if data.starts_with(b"RELAYCHAIN:") {
                    if mock_relay_bytes.len() <= block_count {
                        mock_relay_bytes.push(data[11..].to_vec());
                    }
                    return None;
                }
                // We have reached the limit of block we want to decode
                if MAX_BLOCKS_PER_INPUT != 0 && block_count >= MAX_BLOCKS_PER_INPUT {
                    return None;
                }
                // lapse is u32 (4 bytes), origin is u16 (2 bytes) -> 6 bytes minimum
                let min_data_len = 4 + 2;
                if data.len() <= min_data_len {
                    return None;
                }
                let lapse: u32 = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                let origin: usize = u16::from_ne_bytes(data[4..6].try_into().unwrap()) as usize;
                let mut encoded_extrinsic: &[u8] = &data[6..];

                // If the lapse is in the range [1, MAX_BLOCK_LAPSE] it is valid.
                let maybe_lapse = match lapse {
                    1..=MAX_BLOCK_LAPSE => Some(lapse),
                    _ => None,
                };
                // We have reached the limit of extrinsics for this block
                if maybe_lapse.is_none()
                    && MAX_EXTRINSICS_PER_BLOCK != 0
                    && extrinsics_in_block >= MAX_EXTRINSICS_PER_BLOCK
                {
                    return None;
                }

                match DecodeLimit::decode_with_depth_limit(64, &mut encoded_extrinsic) {
                    Ok(decoded_extrinsic) => {
                        if maybe_lapse.is_some() {
                            block_count += 1;
                            extrinsics_in_block = 1;
                        } else {
                            extrinsics_in_block += 1;
                        }
                        // We have reached the limit of block we want to decode
                        if MAX_BLOCKS_PER_INPUT != 0 && block_count >= MAX_BLOCKS_PER_INPUT {
                            return None;
                        }
                        Some((maybe_lapse, origin, decoded_extrinsic))
                    }
                    Err(_) => None,
                }
            })
            .collect();

        if extrinsics.is_empty() {
            return;
        }

        // `externalities` represents the state of our mock chain.
        let mut externalities = Externalities::new(GENESIS_STORAGE.clone());

        let mut current_block: u32 = 1;
        let mut current_timestamp: u64 = INITIAL_TIMESTAMP;
        let mut current_weight: Weight = Weight::zero();
        //let mut already_seen = 0; // This must be uncommented if you want to print events
        let mut elapsed: Duration = Duration::ZERO;

        let mut start_block = |block: u32, current_timestamp: u64| {
            #[cfg(not(fuzzing))]
            println!("\ninitializing block {block}");

            /*
            let pre_digest = match current_timestamp {
                INITIAL_TIMESTAMP => Default::default(),
                _ => Digest {
                    logs: vec![DigestItem::PreRuntime(
                        AURA_ENGINE_ID,
                        Slot::from(current_timestamp / SLOT_DURATION).encode(),
                    )],
                },
            };
            */
            let pre_digest = match current_timestamp {
                _ => Digest {
                    logs: vec![DigestItem::PreRuntime(
                        AURA_ENGINE_ID,
                        Slot::from(current_timestamp / SLOT_DURATION).encode(),
                    )],
                },
            };

            Executive::initialize_block(&Header::new(
                block,
                Default::default(),
                Default::default(),
                Default::default(),
                pre_digest,
            ));

            // Apply inherents
            use {
                cumulus_primitives_core::PersistedValidationData,
                cumulus_primitives_parachain_inherent::ParachainInherentData,
            };

            // TODO: if there is nothing in mock_relay_bytes, it may be faster to just use
            // RelayStateSproofBuilder::default().into_state_root_and_proof()
            let (
                vfp,
                relay_chain_state,
                downward_messages,
                horizontal_messages,
            ) = {
                // Use MockValidationDataInherentDataProvider
                // Read inherent data and decode it
                use {
                    cumulus_primitives_parachain_inherent::{
                        MockValidationDataInherentDataProvider, MockXcmConfig,
                    },
                    futures::executor::block_on,
                };

                let starting_dmq_mqc_head = {
                    //frame_support::storage::unhashed::get_raw(&[twox_128(b"ParachainSystem"), twox_128(b"LastDmqMqcHead")]
                    frame_support::storage::unhashed::get_raw(&[
                        69, 50, 61, 247, 204, 71, 21, 11, 57, 48, 226, 102, 107, 10, 163, 19, 145,
                        26, 93, 211, 241, 21, 95, 91, 125, 12, 90, 161, 2, 167, 87, 249,
                    ])
                    .map(|raw_data| {
                        Decode::decode(&mut &raw_data[..])
                            .expect("Stored data should decode correctly")
                    })
                    .unwrap_or_default()
                };

                let starting_hrmp_mqc_heads = {
                    /*
                    client
                    .storage(
                        parent_block,
                        &sp_storage::StorageKey(
                            [twox_128(&parachain_system_name), twox_128(b"LastHrmpMqcHeads")]
                                .concat()
                                .to_vec(),
                        ),
                    )
                    .expect("We should be able to read storage from the parent block.")
                    .map(|ref mut raw_data| {
                        Decode::decode(&mut &raw_data.0[..]).expect("Stored data should decode correctly")
                    })
                    .unwrap_or_default()
                    */
                    Default::default()
                };

                let relay_iterable = Data {
                    data: &if mock_relay_bytes.len() > 0 {
                        mock_relay_bytes.remove(0)
                    } else {
                        vec![]
                    },
                    pointer: 0,
                    size: 0,
                };

                let mut raw_downward_messages = vec![];

                // Create a random relay key from this predefined set
                enum RelayKey {
                    DownwardMessages,
                    HorizontalMessages,
                }

                for bytes in relay_iterable {
                    if bytes.len() < 1 {
                        continue;
                    }

                    let key = match bytes[0] {
                        0 => RelayKey::DownwardMessages,
                        1 => RelayKey::HorizontalMessages,
                        _ => {
                            continue;
                        }
                    };

                    let bytes = &bytes[1..];

                    match key {
                        RelayKey::DownwardMessages => {
                            raw_downward_messages.push(bytes.to_vec());
                        }
                        RelayKey::HorizontalMessages => {
                            // not implemented
                        }
                    }
                }

                let mocked_parachain = MockValidationDataInherentDataProvider {
                    current_para_block: block,
                    relay_offset: 1000,
                    relay_blocks_per_para_block: 2,
                    // TODO: Recheck
                    para_blocks_per_relay_epoch: 10,
                    relay_randomness_config: (),
                    xcm_config: MockXcmConfig {
                        para_id: 1000.into(),
                        starting_dmq_mqc_head,
                        starting_hrmp_mqc_heads,
                    },
                    raw_downward_messages,
                    raw_horizontal_messages: vec![],
                    additional_key_values: None,
                };

                let mut inherent_data = sp_inherents::InherentData::new();
                block_on(mocked_parachain.provide_inherent_data(&mut inherent_data)).unwrap();
                let decoded: ParachainInherentData =
                    inherent_data.get_data(b"sysi1337").unwrap().unwrap();

                (
                    decoded.validation_data,
                    decoded.relay_chain_state,
                    decoded.downward_messages,
                    decoded.horizontal_messages,
                )
            };
            let parachain_inherent_data = ParachainInherentData {
                validation_data: vfp,
                relay_chain_state: relay_chain_state.clone(),
                downward_messages,
                horizontal_messages,
            };
            Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(
                RuntimeCall::ParachainSystem(
                    cumulus_pallet_parachain_system::Call::set_validation_data {
                        data: parachain_inherent_data,
                    },
                ),
            ))
            .unwrap()
            .unwrap();

            #[cfg(not(fuzzing))]
            println!("  setting timestamp");
            // We apply the timestamp extrinsic for the current block.
            Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(RuntimeCall::Timestamp(
                pallet_timestamp::Call::set {
                    now: current_timestamp,
                },
            )))
            .unwrap()
            .unwrap();

            Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(
                RuntimeCall::AuthorNoting(pallet_author_noting::Call::set_latest_author_data {
                    data: tp_author_noting_inherent::OwnParachainInherentData {
                        relay_storage_proof: relay_chain_state,
                    },
                }),
            ))
            .unwrap()
            .unwrap();
            // TODO: missing inherents
            // authorInherent.kickOffAuthorshipValidation

            // Calls that need to be called before each block starts (init_calls) go here
        };

        let end_block = |current_block: u32, _current_timestamp: u64| {
            #[cfg(not(fuzzing))]
            println!("  finalizing block {current_block}");
            Executive::finalize_block();

            #[cfg(not(fuzzing))]
            println!("  testing invariants for block {current_block}");
            <AllPalletsWithSystem as TryState<BlockNumber>>::try_state(
                current_block,
                TryStateSelect::All,
            )
            .unwrap();
        };

        externalities.execute_with(|| start_block(current_block, current_timestamp));

        for (maybe_lapse, origin, extrinsic) in extrinsics {
            // If the lapse is in the range [0, MAX_BLOCK_LAPSE] we finalize the block and initialize
            // a new one.
            if let Some(lapse) = maybe_lapse {
                // We end the current block
                externalities.execute_with(|| end_block(current_block, current_timestamp));

                // We update our state variables
                current_block += lapse;
                current_timestamp += lapse as u64 * SLOT_DURATION;
                current_weight = Weight::zero();
                elapsed = Duration::ZERO;

                // We start the next block
                externalities.execute_with(|| start_block(current_block, current_timestamp));
            }

            // We get the current time for timing purposes.
            let now = Instant::now();

            let mut call_weight = Weight::zero();
            // We compute the weight to avoid overweight blocks.
            externalities.execute_with(|| {
                call_weight = extrinsic.get_dispatch_info().weight;
            });

            current_weight = current_weight.saturating_add(call_weight);
            if current_weight.ref_time() >= max_weight.ref_time() {
                #[cfg(not(fuzzing))]
                println!("Skipping because of max weight {}", max_weight);
                continue;
            }

            externalities.execute_with(|| {
                let origin_account = endowed_accounts[origin % endowed_accounts.len()].clone();
                #[cfg(not(fuzzing))]
                {
                    println!("\n    origin:     {:?}", origin_account);
                    println!("    call:       {:?}", extrinsic);
                }
                let _res = extrinsic
                    .clone()
                    .dispatch(RuntimeOrigin::signed(origin_account));
                #[cfg(not(fuzzing))]
                println!("    result:     {:?}", _res);

                // Uncomment to print events for debugging purposes

                /*
                #[cfg(not(fuzzing))]
                {
                    let all_events = dancebox_runtime::System::events();
                    let events: Vec<_> = all_events.clone().into_iter().skip(already_seen).collect();
                    already_seen = all_events.len();
                    println!("  events:     {:?}\n", events);
                }
                */
            });

            elapsed += now.elapsed();
        }

        #[cfg(not(fuzzing))]
        println!("\n  time spent: {:?}", elapsed);
        if elapsed.as_secs() > MAX_TIME_FOR_BLOCK {
            panic!("block execution took too much time")
        }

        // We end the final block
        externalities.execute_with(|| end_block(current_block, current_timestamp));

        // After execution of all blocks.
        externalities.execute_with(|| {
            // We keep track of the sum of balance of accounts
            let mut counted_free = 0;
            let mut counted_reserved = 0;
            let mut _counted_frozen = 0;

            for acc in frame_system::Account::<Runtime>::iter() {
                // Check that the consumer/provider state is valid.
                let acc_consumers = acc.1.consumers;
                let acc_providers = acc.1.providers;
                if acc_consumers > 0 && acc_providers == 0 {
                    panic!("Invalid state");
                }

                // Increment our balance counts
                counted_free += acc.1.data.free;
                counted_reserved += acc.1.data.reserved;
                _counted_frozen += acc.1.data.frozen;
            }

            let total_issuance = pallet_balances::TotalIssuance::<Runtime>::get();
            let counted_issuance = counted_free + counted_reserved;
            if total_issuance != counted_issuance {
                panic!(
                    "Inconsistent total issuance: {total_issuance} but counted {counted_issuance}"
                );
            }

            #[cfg(not(fuzzing))]
            println!("\nrunning integrity tests\n");
            // We run all developer-defined integrity tests
            <AllPalletsWithSystem as IntegrityTest>::integrity_test();
        });
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| { fuzz_main(data) });
