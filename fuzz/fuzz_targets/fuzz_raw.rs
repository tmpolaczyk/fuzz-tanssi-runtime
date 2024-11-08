#![no_main]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Tanssi Runtime fuzz target. Generates random extrinsics and some mock relay validation data (but no sudo).
//!
//! Based on https://github.com/srlabs/substrate-runtime-fuzzer/blob/8d45d9960cff6f6c5aa8bf19808f84ef12b08535/node-template-fuzzer/src/main.rs

use {
    cumulus_primitives_core::ParaId,
    dancebox_runtime::{
        AccountId, AllPalletsWithSystem, BlockNumber, Executive, Header, Runtime, RuntimeCall,
        RuntimeOrigin, Signature, UncheckedExtrinsic, SLOT_DURATION,
    },
    dp_core::well_known_keys::PARAS_HEADS_INDEX,
    frame_metadata::{v15::RuntimeMetadataV15, RuntimeMetadata, RuntimeMetadataPrefixed},
    frame_support::{
        dispatch::GetDispatchInfo,
        pallet_prelude::Weight,
        traits::{IntegrityTest, TryState, TryStateSelect},
        weights::constants::WEIGHT_REF_TIME_PER_SECOND,
        Hashable,
    },
    nimbus_primitives::{NimbusId, NIMBUS_ENGINE_ID},
    parity_scale_codec::{DecodeLimit, Encode},
    sp_consensus_aura::{Slot, AURA_ENGINE_ID},
    sp_core::{sr25519, Decode, Get, Pair, Public},
    sp_inherents::InherentDataProvider,
    sp_runtime::{
        traits::{Dispatchable, Header as HeaderT, IdentifyAccount, Verify},
        Digest, DigestItem, Perbill, Storage,
    },
    std::{
        any::TypeId,
        cell::Cell,
        time::{Duration, Instant},
        marker::PhantomData,
    },
    dp_container_chain_genesis_data::ContainerChainGenesisData,
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

fn recursively_find_call(call: RuntimeCall, matches_on: fn(RuntimeCall) -> bool) -> bool {
    if let RuntimeCall::Utility(
        pallet_utility::Call::batch { calls }
        | pallet_utility::Call::force_batch { calls }
        | pallet_utility::Call::batch_all { calls },
    ) = call
    {
        for call in calls {
            if recursively_find_call(call.clone(), matches_on) {
                return true;
            }
        }
    }
    /*
    else if let RuntimeCall::Lottery(pallet_lottery::Call::buy_ticket { call })
    | RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
        call, ..
    })
    | RuntimeCall::Utility(pallet_utility::Call::as_derivative { call, .. })
    | RuntimeCall::Council(pallet_collective::Call::propose {
        proposal: call, ..
    }) = call
    {
        return recursively_find_call(*call.clone(), matches_on);
    }
    */
    else if matches_on(call) {
        return true;
    }
    false
}

/// Return true if the root origin can execute this extrinsic.
/// Any extrinsic that could brick the chain should be disabled, we only want to test real-world scenarios.
fn root_can_call(call: &RuntimeCall) -> bool {
    match call {
        // Allow root to call any pallet_registrar extrinsic, as it is unlikely to brick the chain
        // TODO: except register(1000), because that may actually break some things
        RuntimeCall::Registrar(..) => true,
        // Allow root to call pallet_author_noting killAuthorData
        RuntimeCall::AuthorNoting(pallet_author_noting::pallet::Call::kill_author_data {
            ..
        }) => true,
        RuntimeCall::Invulnerables(call_invulnerables) => {
            // Allow root to add any invulnerable
            if let pallet_invulnerables::pallet::Call::add_invulnerable { .. } = call_invulnerables
            {
                return true;
            }
            // Allow root to remove any invulnerable except Alice
            match call_invulnerables {
                pallet_invulnerables::pallet::Call::remove_invulnerable { who }
                    if *who != *ALICE =>
                {
                    return true;
                }
                _ => {}
            }

            false
        }
        // Allow root to start and stop maintenance mode
        RuntimeCall::MaintenanceMode(..) => true,
        // Allow root to pause/unpause any extrinsic
        RuntimeCall::TxPause(..) => true,
        // Allow root to change configuration, except using set_bypass_consistency_check
        RuntimeCall::Configuration(call_configuration) => {
            if let pallet_configuration::pallet::Call::set_bypass_consistency_check { .. } =
                call_configuration
            {
                false
            } else {
                true
            }
        }
        _ => false,
    }
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public + 'static>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    static ACCOUNT_FROM_SEED: &[(&str, &str)] = &[
        (
            "Alice",
            "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
        ),
        (
            "Bob",
            "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48",
        ),
        (
            "Charlie",
            "90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22",
        ),
        (
            "Dave",
            "306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20",
        ),
    ];
    // When compiled with `--cfg fuzzing`, this doesn't work because of an invalid bip39 checksum error
    // caused by the `bitcoin_hashes` library, which mocks sha256 when fuzzing.
    // To avoid this problem, generate the public key some other way and add it to the account list above.
    if let Some(hex_key) =
        ACCOUNT_FROM_SEED
            .iter()
            .find_map(|(k, v)| if *k == seed { Some(v) } else { None })
    {
        let mut x: <TPublic::Pair as Pair>::Public =
            if TypeId::of::<TPublic>() == TypeId::of::<sr25519::Public>() {
                unsafe { std::mem::zeroed() }
            } else if TypeId::of::<TPublic>() == TypeId::of::<NimbusId>() {
                unsafe { std::mem::zeroed() }
            } else {
                unimplemented!()
            };
        let xm = x.as_mut();
        xm.copy_from_slice(&hex::decode(hex_key).unwrap());
        return x;
    }
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

pub fn mock_container_chain_genesis_data(
    para_id: ParaId,
) -> ContainerChainGenesisData {
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
    let res = get_from_seed::<NimbusId>(seed);
    //println!("NimbusId {:?} {:?}", seed, res);
    res
}

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public + 'static>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    let res = AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account();
    //println!("AccountId {:?} {:?}", seed, res);
    res
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

fn get_origin(origin: usize) -> &'static AccountId {
    &VALID_ORIGINS[origin % VALID_ORIGINS.len()]
}

lazy_static::lazy_static! {
    static ref ALICE: AccountId = INTERESTING_ACCOUNTS[4].clone();
    static ref VALID_ORIGINS: Vec<AccountId> = {
        let endowed_accounts: Vec<AccountId> = (0..4).map(|i| [i; 32].into()).collect();
        let invulnerables = vec![
                "Alice".to_string(),
                "Bob".to_string(),
                "Charlie".to_string(),
                "Dave".to_string(),
        ];
        let invulnerables = invulnerables_from_seeds(invulnerables.iter());

        endowed_accounts.into_iter().chain(
            invulnerables.into_iter().map(|x| x.0)
        ).collect()
    };
    static ref INTERESTING_ACCOUNTS: Vec<AccountId> = {
        let accounts_with_ed = vec![
            dancebox_runtime::StakingAccount::get(),
            dancebox_runtime::ParachainBondAccount::get(),
            dancebox_runtime::PendingRewardsAccount::get(),
        ];

        VALID_ORIGINS.iter().cloned().chain(
            accounts_with_ed.into_iter()
        ).collect()
    };
    static ref INTERESTING_PARA_IDS: Vec<u32> = {
        vec![
            // Self
            1000,
            // Registered
            2000,
            2001,
        ]
    };

    static ref GENESIS_STORAGE: Storage = {
        let mut endowed_accounts: Vec<AccountId> = (0..4).map(|i| [i; 32].into()).collect();

        let genesis_storage: Storage = {
            use sp_runtime::BuildStorage;
            use dp_container_chain_genesis_data::json::container_chain_genesis_data_from_path;
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
            endowed_accounts.extend(invulnerables.iter().map(|x| x.0.clone()));
            let para_ids: Vec<_> = container_chains
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
                .collect();
            // Assign 1000 block credits and 100 session credits to all container chains registered in genesis
            let para_id_credits: Vec<_> = para_ids
                .iter()
                .map(|(para_id, _genesis_data, _boot_nodes)| (*para_id, 1000, 100).into())
                .collect();
            let para_id_boot_nodes: Vec<_> = para_ids
                .iter()
                .map(|(para_id, _genesis_data, boot_nodes)| (*para_id, boot_nodes.clone()))
                .collect();
            let para_ids: Vec<_> = para_ids
                .into_iter()
                .map(|(para_id, genesis_data, _boot_nodes)| (para_id, genesis_data, None))
                .collect();
            let accounts_with_ed = vec![
                dancebox_runtime::StakingAccount::get(),
                dancebox_runtime::ParachainBondAccount::get(),
                dancebox_runtime::PendingRewardsAccount::get(),
            ];

            dancebox_runtime::RuntimeGenesisConfig {
                system: dancebox_runtime::SystemConfig {
                    ..Default::default()
                },
                balances: dancebox_runtime::BalancesConfig {
                    balances: endowed_accounts
                        .iter()
                        .cloned()
                        .map(|k| (k, 1 << 60))
                        .chain(
                            accounts_with_ed
                                .iter()
                                .cloned()
                                .map(|k| (k, dancebox_runtime::EXISTENTIAL_DEPOSIT))
                        )
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
                    ..Default::default()
                },
                parachain_system: Default::default(),
                configuration: dancebox_runtime::ConfigurationConfig {
                        config: pallet_configuration::HostConfiguration {
                            max_collators: 100u32,
                            min_orchestrator_collators: 1u32,
                            max_orchestrator_collators: 1u32,
                            collators_per_container: 2u32,
                            full_rotation_period: prod_or_fast!(24u32, 5u32),
                            collators_per_parathread: 1,
                            parathreads_per_collator: 1,
                            target_container_chain_fullness: Perbill::from_percent(80),
                            max_parachain_cores_percentage: None,
                        },
                        ..Default::default()
                },
                registrar: dancebox_runtime::RegistrarConfig { para_ids, phantom: PhantomData },
                data_preservers: dancebox_runtime::DataPreserversConfig::default(),
                services_payment: dancebox_runtime::ServicesPaymentConfig { para_id_credits },
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
                tx_pause: Default::default(),
                treasury: Default::default(),
            }
            .build_storage()
            .unwrap()
        };

        genesis_storage
    };

    static ref METADATA: RuntimeMetadataV15 = {
        let metadata_bytes = &Runtime::metadata_at_version(15)
            .expect("Metadata must be present; qed");

        let metadata: RuntimeMetadataPrefixed =
            Decode::decode(&mut &metadata_bytes[..]).expect("Metadata encoded properly; qed");

        let metadata: RuntimeMetadataV15 = match metadata.1 {
            RuntimeMetadata::V15(metadata) => metadata,
            _ => panic!("metadata has been bumped, test needs to be updated"),
        };

        metadata
    };

    static ref RUNTIME_API_NAMES: Vec<String> = {
        let mut v = vec![];

        for api in METADATA.apis.iter() {
            for method in api.methods.iter() {
                v.push(format!("{}_{}", api.name, method.name));
            }
        }

        v.sort();

        v
    };
}

#[derive(Debug, Encode, Decode)]
enum FuzzRuntimeCall {
    SetRelayData(Vec<u8>),
    CallRuntimeApi(Vec<u8>),
}

#[derive(Debug)]
enum ExtrOrPseudo {
    Extr(RuntimeCall),
    Pseudo(FuzzRuntimeCall),
}

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
    // Uncomment to init logger
    //*LOGGER;
    //println!("data: {:?}", data);
    let iteratable = Data {
        data: &data,
        pointer: 0,
        size: 0,
    };

    // Max weight for a block.
    let max_weight: Weight = Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND * 2, 0);

    let mut block_count = 0;
    let mut extrinsics_in_block = 0;
    let mock_relay_bytes: Cell<Vec<u8>> = Cell::new(vec![]);

    let mut extrinsics: Vec<(Option<u32>, usize, ExtrOrPseudo)> =
        Vec::with_capacity(MAX_BLOCKS_PER_INPUT * (MAX_EXTRINSICS_PER_BLOCK + 1));
    let iterable = iteratable.filter_map(|data| {
        // We have reached the limit of block we want to decode
        if MAX_BLOCKS_PER_INPUT != 0 && block_count >= MAX_BLOCKS_PER_INPUT {
            return None;
        }
        // lapse is u32 (4 bytes), origin is u16 (2 bytes) -> 6 bytes minimum
        let min_data_len = 4 + 2;
        if data.len() <= min_data_len {
            return None;
        }
        let lapse: u32 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let origin: usize = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
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

        if let Some(mut pseudo_extrinsic) = encoded_extrinsic.strip_prefix(b"\xff\xff\xff\xff") {
            match FuzzRuntimeCall::decode_with_depth_limit(64, &mut pseudo_extrinsic) {
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
                    return Some((maybe_lapse, origin, ExtrOrPseudo::Pseudo(decoded_extrinsic)));
                }
                Err(_) => return None,
            }
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
                Some((maybe_lapse, origin, ExtrOrPseudo::Extr(decoded_extrinsic)))
            }
            Err(_) => None,
        }
    });
    extrinsics.extend(iterable);

    //println!("{:?}", extrinsics);

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
    let parent_hash = Cell::new(None);
    let parent_header = Cell::new(None);

    let start_block = |block: u32, current_timestamp: u64| {
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
        let aura_slot = current_timestamp / SLOT_DURATION;
        fn guess_author(slot: usize, block: u32) -> NimbusId {
            use pallet_session::ShouldEndSession;
            // Check whether we need to fetch the next authorities or current ones
            // Cannot use `Runtime::authorities()` here because that would use `parent_block_number + 1`, but that is not the same
            // as `block` when there are block gaps (lapse > 1).
            let should_end_session =
                <Runtime as pallet_session::Config>::ShouldEndSession::should_end_session(block);

            let session_index = if should_end_session {
                dancebox_runtime::Session::current_index() + 1
            } else {
                dancebox_runtime::Session::current_index()
            };
            let authorities =
                pallet_authority_assignment::CollatorContainerChain::<Runtime>::get(session_index)
                    .expect("authorities for current session should exist")
                    .orchestrator_chain;

            if authorities.len() == 0 {
                panic!("Stalled chain, no authoritiy can author next block");
            }
            let author_index = slot % authorities.len();
            let expected_author = &authorities[author_index];

            //println!("guess_author: slot={}, authorities.len()={}, author={:?}", slot, authorities.len(), expected_author);
            //println!("guess_author authorities: {:?}", authorities);

            expected_author.clone()
        }
        let author = guess_author(aura_slot as usize, block);

        let pre_digest = match current_timestamp {
            _ => Digest {
                logs: vec![
                    DigestItem::PreRuntime(AURA_ENGINE_ID, Slot::from(aura_slot).encode()),
                    DigestItem::PreRuntime(NIMBUS_ENGINE_ID, NimbusId::from(author).encode()),
                ],
            },
        };

        Executive::initialize_block(&Header::new(
            block,
            Default::default(),
            Default::default(),
            parent_hash.take().unwrap_or_default(),
            pre_digest.clone(),
        ));

        // Apply inherents
        use {
            cumulus_primitives_core::PersistedValidationData,
            cumulus_primitives_parachain_inherent::ParachainInherentData,
        };

        let (vfp, relay_chain_state, downward_messages, horizontal_messages) = {
            // Use MockValidationDataInherentDataProvider
            // Read inherent data and decode it
            use {
                cumulus_client_parachain_inherent::{
                    MockValidationDataInherentDataProvider, MockXcmConfig,
                },
                futures::executor::block_on,
            };

            let starting_dmq_mqc_head = {
                //frame_support::storage::unhashed::get_raw(&[twox_128(b"ParachainSystem"), twox_128(b"LastDmqMqcHead")]
                frame_support::storage::unhashed::get_raw(&[
                    69, 50, 61, 247, 204, 71, 21, 11, 57, 48, 226, 102, 107, 10, 163, 19, 145, 26,
                    93, 211, 241, 21, 95, 91, 125, 12, 90, 161, 2, 167, 87, 249,
                ])
                .map(|raw_data| {
                    Decode::decode(&mut &raw_data[..]).expect("Stored data should decode correctly")
                })
                .unwrap_or_default()
            };

            let starting_hrmp_mqc_heads = {
                //frame_support::storage::unhashed::get_raw(&[twox_128(b"ParachainSystem"), twox_128(b"LastHrmpMqcHeads")]
                frame_support::storage::unhashed::get_raw(&[
                    69, 50, 61, 247, 204, 71, 21, 11, 57, 48, 226, 102, 107, 10, 163, 19, 61, 202,
                    66, 222, 176, 8, 198, 85, 158, 231, 137, 201, 185, 247, 10, 44,
                ])
                .map(|raw_data| {
                    Decode::decode(&mut &raw_data[..]).expect("Stored data should decode correctly")
                })
                .unwrap_or_default()
            };

            // Take value of `mock_relay_bytes`, it will only be used for this block and set to [] afterwards,
            // unless the next block also sets a custom relay data
            let mock_relay_bytes_l = mock_relay_bytes.take();
            let relay_iterable = RelayData {
                data: &mock_relay_bytes_l,
                pointer: 0,
                size: 0,
            };

            let mut raw_downward_messages = vec![];
            let mut raw_horizontal_messages = vec![];
            let mut additional_key_values = vec![];
            let mut remove_current_block_randomness = false;

            // Create a random relay key from this predefined set
            #[derive(Encode, Decode)]
            enum FuzzRelayKey {
                DownwardMessages(Vec<u8>),
                HorizontalMessages(Vec<u8>),
                ParasHeads { known_para_id: u8, data: Vec<u8> },
                RemoveCurrentBlockRandomness,
            }

            for mut bytes in relay_iterable {
                let relay_key = match FuzzRelayKey::decode_with_depth_limit(64, &mut bytes) {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                match relay_key {
                    FuzzRelayKey::DownwardMessages(data) => {
                        if data.len() < 1 {
                            // Empty input makes try_state check fail in MessageQueue:
                            // Other("There must be some message size if in ReadyRing")
                            // [100, 136, 255, 255, 255, 255, 255, 255, 255, 255, 0, 40, 0, 0, 0, 76, 47, 47, 5, 255, 255, 255]
                            continue;
                        }
                        raw_downward_messages.push(data);
                    }
                    FuzzRelayKey::HorizontalMessages(_data) => {
                        // Disabled because we hit debug_asserts:
                        // thread '<unnamed>' panicked at /home/tomasz/.cargo/git/checkouts/polkadot-sdk-df3be1d6828443a1/b3aad07/cumulus/pallets/xcmp-queue/src/lib.rs:970:21:
                        // Unknown XCMP message format. Silently dropping message
                        /*
                        // 4 bytes para id
                        if bytes.len() < 4 {
                            continue;
                        }
                        let para_id = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                        let value = bytes[4..].to_vec();
                        raw_horizontal_messages.push((para_id.into(), value));
                        */
                    }
                    FuzzRelayKey::ParasHeads {
                        known_para_id,
                        data,
                    } => {
                        let para_id_val = known_para_id;
                        let mut para_id = INTERESTING_PARA_IDS.get(para_id_val as usize).copied();
                        let mut bytes = &data[..];
                        if para_id.is_none() {
                            // Random para id
                            if bytes.len() < 4 {
                                continue;
                            }
                            let mut para_id_bytes = [0; 4];
                            para_id_bytes.copy_from_slice(&bytes[..4]);
                            // Advance bytes for value
                            bytes = &bytes[4..];
                            para_id = Some(u32::from_le_bytes(para_id_bytes));
                        };
                        let para_id = para_id.unwrap();
                        if para_id == 1000 {
                            // Setting a custom ParasHeads value for our para id results in this
                            // panic:
                            // thread '<unnamed>' panicked at /home/tomasz/.cargo/git/checkouts/polkadot-sdk-df3be1d6828443a1/b3aad07/cumulus/pallets/parachain-system/src/lib.rs:1218:17:
                            // assertion `left == right` failed: expected parent to be included
                            continue;
                        }
                        let paraid_bytes = para_id.twox_64_concat();
                        // CONCAT
                        let key = [PARAS_HEADS_INDEX, paraid_bytes.as_slice()].concat();
                        let value = bytes.to_vec();
                        additional_key_values.push((key, value));
                    }
                    /*
                    RelayKey::CurrentBlockRandomness => {
                        if bytes.len() < 1 {
                            continue;
                        }
                        let key = cumulus_primitives_core::relay_chain::well_known_keys::CURRENT_BLOCK_RANDOMNESS;
                        let mut value = [bytes[0]; 32];
                        // Ensure different randomness in different blocks
                        value[0..4].copy_from_slice(&block.to_le_bytes());
                        // Avoid case of randomness 000000
                        value[31] |= 1;
                        additional_key_values.push((key.to_vec(), value.to_vec()));
                    }
                    */
                    FuzzRelayKey::RemoveCurrentBlockRandomness => {
                        remove_current_block_randomness = true;
                    }
                }
            }

            // Add randomness unless explicitly removed
            if !remove_current_block_randomness {
                let key =
                    cumulus_primitives_core::relay_chain::well_known_keys::CURRENT_BLOCK_RANDOMNESS;
                let mut value = [0; 32];
                // Ensure different randomness in different blocks
                value[0..4].copy_from_slice(&block.to_le_bytes());
                // Avoid case of randomness 000000
                value[31] |= 1;
                additional_key_values.push((key.to_vec(), Some(value).encode()));
            }

            {
                let para_header = parent_header.take().unwrap_or_else(|| {
                    // Header of genesis block
                    Header::new(
                        0,
                        Default::default(),
                        Default::default(),
                        Default::default(),
                        Default::default(),
                    )
                });
                let para_head_key =
                    cumulus_primitives_core::relay_chain::well_known_keys::para_head(ParaId::from(
                        1000,
                    ));
                let para_head_data =
                    cumulus_primitives_core::relay_chain::HeadData(para_header.encode()).encode();
                additional_key_values.push((para_head_key, para_head_data));
            }

            {
                let relay_slot_key =
                    cumulus_primitives_core::relay_chain::well_known_keys::CURRENT_SLOT.to_vec();
                let relay_slot = aura_slot;
                additional_key_values.push((relay_slot_key, Slot::from(relay_slot).encode()));
            }

            let mocked_parachain = MockValidationDataInherentDataProvider {
                current_para_block: block,
                current_para_block_head: None, // TODO
                relay_offset: 1000,
                relay_blocks_per_para_block: 2,
                // TODO: Recheck
                para_blocks_per_relay_epoch: 10,
                // Randomness is just session number
                relay_randomness_config: (),
                xcm_config: MockXcmConfig {
                    starting_dmq_mqc_head,
                    starting_hrmp_mqc_heads,
                },
                para_id: 1000.into(),
                raw_downward_messages,
                raw_horizontal_messages,
                additional_key_values: Some(additional_key_values),
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

        Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(RuntimeCall::AuthorNoting(
            pallet_author_noting::Call::set_latest_author_data {
                data: tp_author_noting_inherent::OwnParachainInherentData {
                    relay_storage_proof: relay_chain_state,
                },
            },
        )))
        .unwrap()
        .unwrap();

        Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(
            RuntimeCall::AuthorInherent(
                pallet_author_inherent::Call::kick_off_authorship_validation {},
            ),
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
        let header = Executive::finalize_block();
        parent_hash.set(Some(header.hash()));
        parent_header.set(Some(header));

        // Per block try-state disabled for performance, we only check it once at the end
        /*
        #[cfg(not(fuzzing))]
        println!("  testing invariants for block {current_block}");
        <AllPalletsWithSystem as TryState<BlockNumber>>::try_state(
            current_block,
            TryStateSelect::All,
        )
        .unwrap();
        */
    };

    externalities.execute_with(|| start_block(current_block, current_timestamp));

    //println!("extrinsics {:?}", extrinsics);

    for (maybe_lapse, origin, extrinsic) in extrinsics {
        // If the lapse is in the range [0, MAX_BLOCK_LAPSE] we finalize the block and initialize
        // a new one.
        // TODO: what if lapse is 0, isn't that invalid state?
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

        let extrinsic = match extrinsic {
            ExtrOrPseudo::Extr(extrinsic) => extrinsic,
            ExtrOrPseudo::Pseudo(fuzz_call) => {
                match fuzz_call {
                    // Set relay data and start a new block
                    FuzzRuntimeCall::SetRelayData(x) => {
                        mock_relay_bytes.set(x);

                        let lapse = 1;
                        // We end the current block
                        externalities.execute_with(|| end_block(current_block, current_timestamp));

                        // We update our state variables
                        current_block += lapse;
                        current_timestamp += lapse as u64 * SLOT_DURATION;
                        current_weight = Weight::zero();
                        elapsed = Duration::ZERO;

                        // We start the next block
                        externalities
                            .execute_with(|| start_block(current_block, current_timestamp));
                    }
                    FuzzRuntimeCall::CallRuntimeApi(x) => {
                        // Disabled because anything related to block building will panic
                        continue;
                        if x.len() < 4 {
                            continue;
                        }
                        let method_idx: u32 = u32::from_le_bytes(x[0..4].try_into().unwrap());
                        let raw_data: &[u8] = &x[4..];
                        let method = match RUNTIME_API_NAMES.get(method_idx as usize) {
                            Some(x) => x,
                            None => continue,
                        };

                        if method == "TryRuntime_on_runtime_upgrade" {
                            // Will panic with message:
                            // called `Result::unwrap()` on an `Err` value: Other("On chain and
                            // current storage version do not match. Missing runtime upgrade?")
                            continue;
                        }
                        if method == "SessionKeys_generate_session_keys" {
                            // Will panic because there is no keystore in this context:
                            // No `keystore` associated for the current context!
                            continue;
                        }
                        if method.starts_with("BlockBuilder") {
                            // BlockBuilder api must hold additional preconditions so we are not
                            // testing it.
                            // Will panic if no inherents included with message:
                            // Timestamp must be updated once in the block
                            continue;
                        }

                        //println!("Calling runtime api: {}", method);

                        /*
                        // Method must be a string, so use \0 as separator
                        let split_index = x.iter().position(|x| *x == 0);
                        let (method, raw_data) = match split_index {
                            Some(index) => ( &x[..index], &x[index + 1..] ),
                            None => ( &x[..], &[][..] ),
                        };
                        let method = match std::str::from_utf8(method) {
                            Ok(x) => x,
                            Err(_e) => continue,
                        };
                        */
                        // Ignore panics because `dancebox_runtime::api::dispatch` panics on
                        // invalid input, and we have no easy way to validate the input here.
                        // TODO: this is not thread safe, but that only matters for the coverage script
                        // It can be made thread safe by setting a global panic hook before starting the
                        // main loop, and that panic hook would have methods to disable printing panics
                        // depending on the thread.
                        let panic_hook = std::panic::take_hook();
                        std::panic::set_hook(Box::new(|_| {}));
                        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            externalities
                                .execute_with(|| dancebox_runtime::api::dispatch(method, raw_data))
                        }));
                        std::panic::set_hook(panic_hook);

                        match res {
                            Ok(res) => {
                                // None means RuntimeApi not found, Some(x) means it worked, and x is the
                                // encoded result of the RuntimeApi.
                                // We know the RuntimeApi exists because we are reading the method from
                                // metadata, so assert that it is not None.
                                assert_ne!(res, None);
                            }
                            Err(e) => {
                                fn error_msg_starts_with(
                                    e: &(dyn std::any::Any + Send),
                                    start: &str,
                                ) -> bool {
                                    if let Some(s) = e.downcast_ref::<String>() {
                                        s.starts_with(start)
                                    } else if let Some(s) = e.downcast_ref::<&'static str>() {
                                        s.starts_with(start)
                                    } else {
                                        false
                                    }
                                }
                                if error_msg_starts_with(&*e, "Bad input data provided to ") {
                                    // Ignore, we simply provided invalid input for the RuntimeApi
                                } else {
                                    // resume_unwind does not print the panic message
                                    //std::panic::resume_unwind(e);
                                    if let Some(s) = e.downcast_ref::<String>() {
                                        panic!("{}", s);
                                    } else if let Some(s) = e.downcast_ref::<&'static str>() {
                                        panic!("{}", s);
                                    } else {
                                        panic!("panic_any");
                                    }
                                }
                            }
                        }
                    }
                }
                continue;
            }
        };

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
            let origin = if origin == 0 {
                // Check if this extrinsic can be called by root, if not return a Signed origin
                if root_can_call(&extrinsic) {
                    RuntimeOrigin::root()
                } else {
                    RuntimeOrigin::signed(get_origin(origin).clone())
                }
            } else {
                RuntimeOrigin::signed(get_origin(origin).clone())
            };
            #[cfg(not(fuzzing))]
            {
                println!("\n    origin:     {:?}", origin);
                println!("    call:       {:?}", extrinsic);
            }
            let _res = extrinsic.dispatch(origin);
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
            panic!("Inconsistent total issuance: {total_issuance} but counted {counted_issuance}");
        }

        #[cfg(not(fuzzing))]
        println!("  testing invariants for block {current_block}");
        <AllPalletsWithSystem as TryState<BlockNumber>>::try_state(
            current_block,
            TryStateSelect::All,
        )
        .unwrap();

        #[cfg(not(fuzzing))]
        println!("\nrunning integrity tests\n");
        // We run all developer-defined integrity tests
        <AllPalletsWithSystem as IntegrityTest>::integrity_test();
    });
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| { fuzz_main(data) });

libfuzzer_sys::fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        let mut data = data;
        let cap = data.len();
        let new_size = libfuzzer_sys::fuzzer_mutate(&mut data, size, cap);
        mutate_interesting_accounts(&mut data[..new_size]);
        mutate_interesting_para_ids(&mut data[..new_size]);

        new_size
    }
);
