#![no_main]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Tanssi Runtime fuzz target. Generates random extrinsics and some pseudo-extrinsics.
//!
//! Based on https://github.com/srlabs/substrate-runtime-fuzzer/blob/2a42a8b750aff0e12eb0e09b33aea9825a40595a/runtimes/kusama/src/main.rs

use std::cmp::min;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use frame_support::dispatch::{CallableCallFor as CallableCallForG, DispatchClass, DispatchResultWithPostInfo};
use dancelight_runtime::{AuthorNoting, ExternalValidators, OriginCaller};
use dancelight_runtime::CollatorsInflationRatePerBlock;
use dancelight_runtime::ValidatorsInflationRatePerEra;
use dancelight_runtime::ContainerRegistrar;
use frame_support::traits::Currency;
use dancelight_runtime::InflationRewards;
use sp_trie::GenericMemoryDB;
use sp_trie::cache::{CacheSize, SharedTrieCache};
use sp_state_machine::MemoryDB;
use sp_runtime::traits::BlakeTwo256;
use sp_storage::StateVersion;
use sp_state_machine::LayoutV1;
use sp_state_machine::TrieBackend;
use sp_state_machine::TrieBackendBuilder;
use sp_state_machine::Ext;
use frame_support::storage::unhashed;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use parity_scale_codec::Output;
use sp_runtime::{DispatchError, DispatchErrorWithPostInfo};
use {
    cumulus_primitives_core::ParaId,
    dancelight_runtime::{
        genesis_config_presets::get_authority_keys_from_seed, AccountId, AllPalletsWithSystem,
        Balance, Balances, Executive, Header, ParaInherent, Runtime, RuntimeCall, RuntimeOrigin,
        Timestamp, UncheckedExtrinsic,
    },
    dancelight_runtime_constants::time::SLOT_DURATION,
    dp_container_chain_genesis_data::ContainerChainGenesisData,
    dp_core::well_known_keys::PARAS_HEADS_INDEX,
    frame_metadata::{v15::RuntimeMetadataV15, RuntimeMetadata, RuntimeMetadataPrefixed},
    frame_support::{
        dispatch::GetDispatchInfo,
        pallet_prelude::Weight,
        traits::{IntegrityTest, OriginTrait, TryState, TryStateSelect},
        weights::constants::WEIGHT_REF_TIME_PER_SECOND,
        Hashable,
    },
    frame_system::Account,
    nimbus_primitives::{NimbusId, NIMBUS_ENGINE_ID},
    pallet_balances::{Holds, TotalIssuance},
    pallet_configuration::HostConfiguration,
    parity_scale_codec::{DecodeLimit, Encode},
    polkadot_core_primitives::{BlockNumber, Signature},
    primitives::{SchedulerParams, ValidationCode},
    sp_consensus_aura::{Slot, AURA_ENGINE_ID},
    sp_consensus_babe::{
        digests::{PreDigest, SecondaryPlainPreDigest},
        BABE_ENGINE_ID,
    },
    sp_core::{sr25519, Decode, Get, Pair, Public, H256},
    sp_inherents::InherentDataProvider,
    sp_runtime::{
        traits::{Dispatchable, Header as HeaderT, IdentifyAccount, Verify},
        Digest, DigestItem, Perbill, Saturating, Storage,
    },
    sp_state_machine::BasicExternalities,
    std::{
        any::TypeId,
        sync::Arc,
        cell::Cell,
        cmp::max,
        collections::BTreeMap,
        iter,
        marker::PhantomData,
        time::{Duration, Instant},
    },
};

type CallableCallFor<A, R = Runtime> = CallableCallForG<A, R>;

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
    } else if let RuntimeCall::Multisig(pallet_multisig::Call::as_multi_threshold_1 {
        call, ..
    })
    | RuntimeCall::Utility(pallet_utility::Call::as_derivative { call, .. })
    | RuntimeCall::Proxy(pallet_proxy::Call::proxy { call, .. }) = call
    {
        return recursively_find_call(*call.clone(), matches_on);
    } else if matches_on(call) {
        return true;
    }
    false
}

/// Return true if the none origin can execute this extrinsic.
fn none_can_call(call: &RuntimeCall) -> bool {
    match call {
        // This panics:
        // DidSetContainerAuthorData must be updated only once in a block
        RuntimeCall::AuthorNoting(CallableCallFor::<AuthorNoting>::set_latest_author_data { .. }) => false,
        RuntimeCall::Timestamp(CallableCallFor::<Timestamp>::set { .. }) => false,
        _ => true,
    }
}

/// Return true if the root origin can execute this extrinsic.
/// Any extrinsic that could brick the chain should be disabled, we only want to test real-world scenarios.
fn root_can_call(call: &RuntimeCall) -> bool {
    match call {
        // Allow root to call any pallet_registrar extrinsic, as it is unlikely to brick the chain
        // TODO: except register(1000), because that may actually break some things
        RuntimeCall::ContainerRegistrar(..) => true,
        // TODO: enable relay chain registrar?
        RuntimeCall::Registrar(..) => false,
        // Allow root to call pallet_author_noting killAuthorData
        RuntimeCall::AuthorNoting(pallet_author_noting::pallet::Call::kill_author_data {
            ..
        }) => true,
        // Allow root to change configuration, except using set_bypass_consistency_check
        RuntimeCall::CollatorConfiguration(call_configuration) => {
            if let pallet_configuration::pallet::Call::set_bypass_consistency_check { .. } =
                call_configuration
            {
                false
            } else {
                true
            }
        }
        // TODO: enable relay configuration?
        RuntimeCall::Configuration(x) => {
            false
        }
        RuntimeCall::ExternalValidators(x) => match x {
            CallableCallFor::<dancelight_runtime::ExternalValidators>::set_external_validators { .. } => true,
            CallableCallFor::<dancelight_runtime::ExternalValidators>::skip_external_validators { .. } => true,
            CallableCallFor::<dancelight_runtime::ExternalValidators>::add_whitelisted { .. } => true,
            // TODO: check that we don't remove all?
            CallableCallFor::<dancelight_runtime::ExternalValidators>::remove_whitelisted { .. } => true,
            // force_era will not be properly tested because this test only runs for one block
            CallableCallFor::<dancelight_runtime::ExternalValidators>::force_era { .. } => true,
            _ => true,
        }
        RuntimeCall::ExternalValidatorSlashes(x) => match x {
            // Enable all to see what happens
            CallableCallFor::<dancelight_runtime::ExternalValidatorSlashes>::cancel_deferred_slash { .. } => true,
            _ => true,
        }
        RuntimeCall::Utility(x) => match x {
            CallableCallFor::<dancelight_runtime::Utility>::as_derivative { .. } => false,
            CallableCallFor::<dancelight_runtime::Utility>::dispatch_as { .. } => false,
            CallableCallFor::<dancelight_runtime::Utility>::with_weight { .. } => false,
            // Allow root to batch all, but only if root_can_call all calls in batch
            CallableCallFor::<dancelight_runtime::Utility>::batch { calls } => calls.iter().all(root_can_call),
            CallableCallFor::<dancelight_runtime::Utility>::batch_all { calls } => calls.iter().all(root_can_call),
            CallableCallFor::<dancelight_runtime::Utility>::force_batch { calls } => calls.iter().all(root_can_call),
            _ => false,
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

pub fn mock_container_chain_genesis_data(para_id: ParaId) -> ContainerChainGenesisData {
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
pub fn template_session_keys(account: AccountId) -> dancelight_runtime::SessionKeys {
    let authority_keys = get_authority_keys_from_seed(&account.to_string());

    dancelight_runtime::SessionKeys {
        babe: authority_keys.babe.clone(),
        grandpa: authority_keys.grandpa.clone(),
        para_validator: authority_keys.para_validator.clone(),
        para_assignment: authority_keys.para_assignment.clone(),
        authority_discovery: authority_keys.authority_discovery.clone(),
        beefy: authority_keys.beefy.clone(),
        nimbus: authority_keys.nimbus.clone(),
    }
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

fn default_parachains_host_configuration(
) -> runtime_parachains::configuration::HostConfiguration<primitives::BlockNumber> {
    use primitives::{
        node_features::FeatureIndex, AsyncBackingParams, MAX_CODE_SIZE, MAX_POV_SIZE,
    };

    runtime_parachains::configuration::HostConfiguration {
        validation_upgrade_cooldown: 2u32,
        validation_upgrade_delay: 2,
        code_retention_period: 1200,
        max_code_size: MAX_CODE_SIZE,
        max_pov_size: MAX_POV_SIZE,
        max_head_data_size: 32 * 1024,
        max_upward_queue_count: 8,
        max_upward_queue_size: 1024 * 1024,
        max_downward_message_size: 1024 * 1024,
        max_upward_message_size: 50 * 1024,
        max_upward_message_num_per_candidate: 5,
        hrmp_sender_deposit: 0,
        hrmp_recipient_deposit: 0,
        hrmp_channel_max_capacity: 8,
        hrmp_channel_max_total_size: 8 * 1024,
        hrmp_max_parachain_inbound_channels: 4,
        hrmp_channel_max_message_size: 1024 * 1024,
        hrmp_max_parachain_outbound_channels: 4,
        hrmp_max_message_num_per_candidate: 5,
        dispute_period: 6,
        no_show_slots: 2,
        n_delay_tranches: 25,
        needed_approvals: 2,
        relay_vrf_modulo_samples: 2,
        zeroth_delay_tranche_width: 0,
        minimum_validation_upgrade_delay: 5,
        async_backing_params: AsyncBackingParams {
            max_candidate_depth: 3,
            allowed_ancestry_len: 2,
        },
        node_features: bitvec::vec::BitVec::from_element(
            1u8 << (FeatureIndex::ElasticScalingMVP as usize),
        ),
        scheduler_params: SchedulerParams {
            lookahead: 2,
            group_rotation_frequency: 20,
            paras_availability_period: 4,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn check_invariants(block: u32, initial_total_issuance: Balance, block_rewards: u128) {
    // After execution of all blocks, we run invariants
    let mut counted_free = 0;
    let mut counted_reserved = 0;
    for (account, info) in Account::<Runtime>::iter() {
        let consumers = info.consumers;
        let providers = info.providers;
        assert!(!(consumers > 0 && providers == 0), "Invalid c/p state");
        counted_free += info.data.free;
        counted_reserved += info.data.reserved;
        let max_lock: Balance = Balances::locks(&account)
            .iter()
            .map(|l| l.amount)
            .max()
            .unwrap_or_default();
        assert!(
            max_lock <= info.data.frozen,
            "Max lock ({max_lock}) should be less than or equal to frozen balance ({})",
            info.data.frozen
        );
        let sum_holds: Balance = Holds::<Runtime>::get(&account)
            .iter()
            .map(|l| l.amount)
            .sum();
        assert!(
            sum_holds <= info.data.reserved,
            "Sum of all holds ({sum_holds}) should be less than or equal to reserved balance {}",
            info.data.reserved
        );
    }
    // TODO: Total issuance is wrong, even if we don't add any balances on genesis
    let total_issuance = TotalIssuance::<Runtime>::get();
    let counted_issuance = counted_free + counted_reserved;
    assert!(
        total_issuance == counted_issuance,
        "Inconsistent total issuance: {total_issuance} but counted {counted_issuance}"
    );
    assert!(
        total_issuance <= initial_total_issuance.saturating_add(block_rewards),
        "Total issuance {total_issuance} greater than initial issuance {initial_total_issuance} + block rewards {block_rewards}"
    );
    // We run all developer-defined integrity tests
    AllPalletsWithSystem::integrity_test();
    AllPalletsWithSystem::try_state(block, TryStateSelect::All).unwrap();

    // Testing, ensure snapshot import is correct, print top 100 staking candidates
    //let st100 = pallet_pooled_staking::SortedEligibleCandidates::<Runtime>::get();
    //log::info!("{:?}", st100);
    //let st100: Vec<_> = pallet_registrar::ParaGenesisData::<Runtime>::iter().collect();
    //log::info!("{:?}", st100);
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

use create_storage::create_storage;
mod create_storage {
    use super::*;
    use trie_db::TrieDBMut;
    use trie_db::TrieDBMutBuilder;
    use sp_state_machine::TrieMut;
    use sp_state_machine::OverlayedChanges;

    pub fn create_storage(mut overlay: OverlayedChanges<BlakeTwo256>, backend: TrieBackend<MemoryDB<BlakeTwo256>, BlakeTwo256>, root: H256, shared_cache: SharedTrieCache<BlakeTwo256>) -> (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
        let changes = overlay.drain_storage_changes(&backend, StateVersion::V1).unwrap();

        let mut storage = backend.into_storage();
        let mut cache2 = shared_cache.local_cache();
        //let mut root_decoded: H256 = Decode::decode(&mut root1.as_slice()).unwrap();
        let mut root_mut = root.clone();
        let mut triedbmut: TrieDBMut<LayoutV1<BlakeTwo256>> = TrieDBMutBuilder::from_existing(&mut storage, &mut root_mut).with_optional_cache(None).build();

        for (k, v) in changes.main_storage_changes {
            if let Some(v) = v {
                triedbmut.insert(&k, &v).unwrap();
            } else {
                triedbmut.remove(&k).unwrap();
            }
        }

        triedbmut.commit();

        drop(triedbmut);

        (storage, root_mut, shared_cache)
    }
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
            //dancelight_runtime::StakingAccount::get(),
            //dancelight_runtime::ParachainBondAccount::get(),
            //dancelight_runtime::PendingRewardsAccount::get(),
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

    static ref GENESIS_STORAGE: (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) = {
        use serde::Deserialize;
        use sp_runtime::BuildStorage;

        const EXPORTED_STATE_CHAIN_SPEC_JSON: &[u8] = include_bytes!("../dancelight-2025-04-12.json");

        #[derive(Deserialize)]
        struct XXX1 {
            genesis: XXX2,
        }

        #[derive(Deserialize)]
        struct XXX2 {
            raw: XXX3,
        }

        #[derive(Deserialize)]
        struct XXX3 {
            top: BTreeMap<String, String>,
        }

        let x: XXX1 = serde_json::from_slice(EXPORTED_STATE_CHAIN_SPEC_JSON).unwrap();
        let top = x.genesis.raw.top.into_iter().map(|(k, v)| {
            // Need to skip 0x when decoding
            (hex::decode(&k[2..]).unwrap(), hex::decode(&v[2..]).unwrap())
        }).collect();

        let t = Storage {
            top,
            ..Default::default()
        };


        let mut endowed_accounts: Vec<AccountId> = (0..4).map(|i| [i; 32].into()).collect();
        let invulnerables = vec![
            "Alice".to_string(),
            "Bob".to_string(),
            "Charlie".to_string(),
            "Dave".to_string(),
        ];
        let invulnerables = invulnerables_from_seeds(invulnerables.iter());
        endowed_accounts.extend(invulnerables.iter().map(|x| x.0.clone()));
        let accounts_with_ed = vec![
            //dancelight_runtime::StakingAccount::get(),
            //dancelight_runtime::ParachainBondAccount::get(),
            //dancelight_runtime::PendingRewardsAccount::get(),
        ];

        let genesis_balances = endowed_accounts
            .iter()
            .cloned()
            .map(|k| (k, 1 << 60))
            .chain(
                accounts_with_ed
                    .iter()
                    .cloned()
                    .map(|k| (k, dancelight_runtime_constants::currency::EXISTENTIAL_DEPOSIT))
            );

        // Create empty MemoryDB
        let (mut storage, root): (MemoryDB<BlakeTwo256>, _) = GenericMemoryDB::default_with_root();

        let mut overlay = Default::default();
        //let cache_provider = trie_cache::CacheProvider::new();
        let shared_cache = SharedTrieCache::new(CacheSize::new(400_000));
        let cache = shared_cache.local_cache();
        let mut backend: TrieBackend<_, BlakeTwo256> = TrieBackendBuilder::new_with_cache(storage, root, cache).build();

        let extensions = None;
        let mut ext = Ext::new(&mut overlay, &backend, extensions);

        sp_externalities::set_and_run_with_externalities(&mut ext, move || {
            // Initialize genesis keys
            for (k, v) in t.top {
                unhashed::put_raw(&k, &v);
            }

            // Need to manually update balances because using genesis builder overwrites total issuance
            for (account, new_balance) in genesis_balances {
                dancelight_runtime::Balances::force_set_balance(RuntimeOrigin::root(), account.into(), new_balance).unwrap();
            }
        });

        drop(ext);

        create_storage(overlay, backend, root, shared_cache)
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
    SetOrigin {
        // Default: 0 (signed origin)
        origin: u8,
        // Default: true
        retry_as_root: bool,
        // Default: false, will try signed origin first
        try_root_first: bool,
    },
    // Unused
    SetRelayData(Vec<u8>),
    // Unused
    CallRuntimeApi(Vec<u8>),
    // Unused
    RecvEthMsg(Vec<u8>),
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

static EXPORTED_STORAGE: AtomicBool = AtomicBool::new(false);

fn fuzz_main(data: &[u8]) {
    //println!("data: {:?}", data);
    let mut extrinsic_data = data;
    //#[allow(deprecated)]
    let extrinsics: Vec<ExtrOrPseudo> =
        iter::from_fn(|| DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
        .filter(|x| match x {
            ExtrOrPseudo::Extr(x) => !recursively_find_call(x.clone(), |call| {
                // We filter out calls with Fungible(0) as they cause a debug crash
               /*
                matches!(call.clone(), RuntimeCall::XcmPallet(pallet_xcm::Call::execute { message, .. })
                    if matches!(message.as_ref(), staging_xcm::VersionedXcm::V2(staging_xcm::v2::Xcm(msg))
                        if msg.iter().any(|m| matches!(m, staging_xcm::opaque::v2::prelude::BuyExecution { fees: staging_xcm::v2::MultiAsset { fun, .. }, .. }
                            if fun == &staging_xcm::v2::Fungibility::Fungible(0)
                        )
                    )) || matches!(message.as_ref(), staging_xcm::VersionedXcm::V3(staging_xcm::v3::Xcm(msg))
                        if msg.iter().any(|m| matches!(m, staging_xcm::opaque::v3::prelude::BuyExecution { weight_limit: staging_xcm::opaque::v3::WeightLimit::Limited(weight), .. }
                            if weight.ref_time() <= 1
                        ))
                    )
                )
                || matches!(call.clone(), RuntimeCall::XcmPallet(pallet_xcm::Call::transfer_assets_using_type_and_then { assets, ..})
                    if staging_xcm::v2::MultiAssets::try_from(*assets.clone())
                        .map(|assets| assets.inner().iter().any(|a| matches!(a, staging_xcm::v2::MultiAsset { fun, .. }
                            if fun == &staging_xcm::v2::Fungibility::Fungible(0)
                        ))).unwrap_or(false)
                )
               */
                matches!(call.clone(), RuntimeCall::System(_))
                || matches!(
                    &call,
                    RuntimeCall::Referenda(pallet_referenda::Call::submit {
                        proposal_origin: matching_origin,
                        ..
                    }) if RuntimeOrigin::from(*matching_origin.clone()).caller() == RuntimeOrigin::root().caller()
                )
            }),
            ExtrOrPseudo::Pseudo(x) => true,
        })
            .collect();

    if extrinsics.is_empty() {
        return;
    }

    let mut block: u32 = 1;
    let mut weight: Weight = Weight::zero();
    let mut elapsed: Duration = Duration::ZERO;
    let mut block_rewards: Cell<u128> = Cell::new(0);
    let mut last_era: Cell<u32> = Cell::new(0);

    let initialize_block = |block: u32| {
        log::debug!(target: "fuzz::initialize", "\ninitializing block {block}");

        let validators = dancelight_runtime::Session::validators();
        let slot = Slot::from(u64::from(block + 350000000));
        let authority_index = u32::try_from(u64::from(slot) % u64::try_from(validators.len()).unwrap()).unwrap();
        let pre_digest = Digest {
            logs: vec![DigestItem::PreRuntime(
                BABE_ENGINE_ID,
                PreDigest::SecondaryPlain(SecondaryPlainPreDigest {
                    slot,
                    authority_index,
                })
                .encode(),
            )],
        };

        let grandparent_header = Header::new(
            block,
            H256::default(),
            H256::default(),
            <frame_system::Pallet<Runtime>>::parent_hash(),
            pre_digest.clone(),
        );

        let parent_header = Header::new(
            block,
            H256::default(),
            H256::default(),
            grandparent_header.hash(),
            pre_digest,
        );

        // Calculate max expected supply increase
        {
            let registered_para_ids = ContainerRegistrar::registered_para_ids();
            if !registered_para_ids.is_empty() {
                let new_supply_inflation_rewards =
                    CollatorsInflationRatePerBlock::get() * Balances::total_issuance();
                block_rewards.set(block_rewards.get() + new_supply_inflation_rewards);
            }

            if last_era.get() == 0 {
                let era_index = ExternalValidators::current_era().unwrap();
                last_era.set(era_index);
            }
            let era_index = ExternalValidators::current_era().unwrap();
            let mut new_era = false;
            if era_index > last_era.get() {
                new_era = true;
            }
            if new_era {
                let new_supply_validators = ValidatorsInflationRatePerEra::get() * Balances::total_issuance();
                block_rewards.set(block_rewards.get() + new_supply_validators);
            }
        }

        Executive::initialize_block(&parent_header);

        Timestamp::set(RuntimeOrigin::none(), u64::from(block) * SLOT_DURATION + 2_100_000_000_000).unwrap();

        Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(RuntimeCall::AuthorNoting(
            pallet_author_noting::Call::set_latest_author_data { data: () },
        )))
        .unwrap()
        .unwrap();

        ParaInherent::enter(
            RuntimeOrigin::none(),
            primitives::vstaging::InherentData {
                parent_header: grandparent_header,
                backed_candidates: Vec::default(),
                bitfields: Vec::default(),
                disputes: Vec::default(),
            },
        )
        .unwrap();
    };

    let finalize_block = |elapsed: Duration| {
        log::debug!(target: "fuzz::time", "\n  time spent: {elapsed:?}");
        assert!(elapsed.as_secs() <= 2, "block execution took too much time");

        log::debug!(target: "fuzz::finalize", "  finalizing block");
        Executive::finalize_block();
    };

    use sp_runtime::traits::BlakeTwo256;

    use sp_state_machine::OverlayedChanges;
    use sp_state_machine::TrieBackendBuilder;
    use sp_state_machine::Ext;
    let mut overlay = OverlayedChanges::default();
    let (storage, root, _shared_cache) = &*GENESIS_STORAGE;
    let root = *root;
    let backend: TrieBackend<_, BlakeTwo256> = TrieBackendBuilder::new(storage, root).build();
    let extensions = None;
    let mut ext = Ext::new(&mut overlay, &backend, extensions);
    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        // Use lazy_static to cache values that don't depend on fuzzer input
        lazy_static::lazy_static! {
            static ref INITIAL_TOTAL_ISSUANCE: Balance = TotalIssuance::<Runtime>::get();
            static ref NUM_EVENTS_BEFORE: usize = dancelight_runtime::System::events().len();
        }
        let initial_total_issuance = *INITIAL_TOTAL_ISSUANCE;
        let num_events_before = *NUM_EVENTS_BEFORE;

        // The snapshot is saved after the initial on_initialize
        //initialize_block(block);

        // Uncomment to enable exporting storage to hex snapshot file
        // Useful to avoid running runtime upgrade every time, just export the state after the runtime upgrade
        /*
        if EXPORTED_STORAGE.load(std::sync::atomic::Ordering::SeqCst) == false {
            use std::fs::File;
            use std::io::Write;

            // TODO: create enough blocks to ensure migrations have finished
            for _ in 0..3 {
                finalize_block(elapsed);

                block += 1;
                weight = 0.into();
                elapsed = Duration::ZERO;

                initialize_block(block);
            }
            finalize_block(elapsed);

            let all_key_values = {
                let mut res = vec![];
                let mut prefix = vec![];
                while let Some(key) = sp_io::storage::next_key(&prefix) {
                    let value = frame_support::storage::unhashed::get_raw(&key).unwrap();
                    let key = key.to_vec();
                    prefix = key.clone();

                    res.push((key, value));
                }

                res
            };

            let output_file_path = "fuzz_starlight_live_export_state.hexsnap.txt";
            let mut output_file = File::create(output_file_path).inspect_err(|e| {
                log::error!("Failed to create output file: {}", e);
            }).unwrap();

            for (key, value) in all_key_values {
                writeln!(
                    output_file,
                    "\"0x{}\": \"0x{}\",",
                    hex::encode(&key),
                    hex::encode(&value)
                ).expect("failed to writeln");
            }
            output_file.flush().unwrap();
            log::info!("Exported hex snapshot to file {}", output_file_path);

            EXPORTED_STORAGE.store(true, std::sync::atomic::Ordering::SeqCst);
            return;
        }
        */

        // Origin is kind of like a state machine
        // By default we try using Alice, and if we get Err::BadOrigin, we check if root_can_call
        // that extrinsic, and if so retry as root
        let mut origin = 0;
        let mut origin_retry_as_root = true;
        let mut origin_try_root_first = false;
        let mut origin_retry_as_none = true;

        for extrinsic in extrinsics {
            // For testing, only create 1 block, do not even finalize it

            match extrinsic {
                ExtrOrPseudo::Extr(extrinsic) => {
                    /*
                    weight.saturating_accrue(extrinsic.get_dispatch_info().call_weight);
                    weight.saturating_accrue(extrinsic.get_dispatch_info().extension_weight);
                    if weight.ref_time() >= 2 * WEIGHT_REF_TIME_PER_SECOND {
                        log::warn!("Extrinsic would exhaust block weight, skipping");
                        continue;
                    }
                     */
                    // Ignore weight because we will be executing all extrinsics in the same block.
                    // But detect expensive extrinsics that take the whole block.
                    // I tried to panic but there are many edge cases here:
                    // * Disabled extrinsics return a big weight, not u64::MAX, but some random big number different for each extrinsic.
                    //   Examples: set_hrmp_open_request_ttl, force_process_hrmp_close
                    // * Parametric weights can easily overflow. For example, if the weight depends on some param n, and we set n = 1_000_000,
                    //   then the weight will be a million times greater than expected. So in practice this extrinsic cannot be called with this
                    //   arg, so we must skip it here. An example is `RuntimeCall::FellowshipCollective(Call::remove_member {..})`
                    let info = extrinsic.get_dispatch_info();
                    if info.call_weight.ref_time() + info.extension_weight.ref_time() >= 2 * WEIGHT_REF_TIME_PER_SECOND /*&&
                        match &extrinsic {
                            // Whitelist some extrinsics with big weights
                            RuntimeCall::Configuration(runtime_parachains::configuration::Call::set_hrmp_open_request_ttl { .. }) => false,
                            RuntimeCall::Hrmp(CallableCallFor::<dancelight_runtime::Hrmp>::force_process_hrmp_close { .. }) => false,
                            // I guess everything under HRMP is disabled
                            RuntimeCall::Hrmp(..) => false,
                            _ => true,
                        }*/ {
                        //log::error!(target: "fuzz::call", "    call:       {extrinsic:?}");
                        //panic!("Extrinsic would exhaust block weight");
                        continue;
                    }

                    let mut origin_is_root = false;
                    // Disable all root for now
                    origin_retry_as_root = false;
                    origin_try_root_first = false;
                    let origin_u8 = origin;
                    let origin = if origin == 0 {
                        // Check if this extrinsic can be called by root, if not return a Signed origin
                        if origin_try_root_first && root_can_call(&extrinsic) {
                            origin_is_root = true;

                            RuntimeOrigin::root()
                        } else {
                            RuntimeOrigin::signed(get_origin(origin.into()).clone())
                        }
                    } else {
                        RuntimeOrigin::signed(get_origin(origin.into()).clone())
                    };

                    log::debug!(target: "fuzz::origin", "\n    origin:     {origin:?}");
                    log::debug!(target: "fuzz::call", "    call:       {extrinsic:?}");

                    let now = Instant::now(); // We get the current time for timing purposes.
                    #[allow(unused_variables)]
                    let mut res = extrinsic.clone().dispatch(origin.clone());
                    elapsed += now.elapsed();
                    //let mut res: DispatchResultWithPostInfo = Err(DispatchErrorWithPostInfo { post_info: Default::default(), error: DispatchError::BadOrigin });

                    if origin_retry_as_root {
                        if let Err(e) = &res {
                            if let DispatchError::BadOrigin = &e.error {
                                // Retry using a different origin
                                let origin = if origin_is_root {
                                    // First we tried as root, now retry as signed origin
                                    Some(RuntimeOrigin::signed(get_origin(origin_u8.into()).clone()))
                                } else {
                                    // Retry as root if allowed
                                    if root_can_call(&extrinsic) {
                                        Some(RuntimeOrigin::root())
                                    } else {
                                        // If not allowed, do not retry
                                        None
                                    }
                                };
                                if let Some(origin) = origin {
                                    log::debug!(target: "fuzz::result", "    result:     {}", match &res {
                                        Ok(x) => {
                                            if let Some(w) = x.actual_weight {
                                                format!("Ok {{ actual_weight: {:?} }}", w)
                                            } else {
                                                format!("Ok {{ }}")
                                            }
                                        }
                                        Err(e) => {
                                            if let Some(w) = e.post_info.actual_weight {
                                                format!("Err {{ error: {:?}, actual_weight: {:?} }}", e.error, w)
                                            } else {
                                                format!("Err {{ error: {:?} }}", e.error)
                                            }
                                        }
                                    });

                                    log::debug!(target: "fuzz::origin", "\n    origin:     {origin:?}");
                                    log::debug!(target: "fuzz::call", "    call:       {extrinsic:?}");

                                    res = extrinsic.clone().dispatch(origin);
                                }
                            }
                        }
                    }

                    // Panic if none origin is able to execute any extrinsic that is not manually
                    // whitelisted in `none_can_call`
                    if origin_retry_as_none {
                        // Mandatory extrinsics have ensure_none origin but
                        // they will panic if we try to include them using rpc
                        // See function validate_transaction in
                        // substrate/frame/executive/src/lib.rs
                        let is_mandatory = match info.class {
                            DispatchClass::Mandatory => {
                                true
                            }
                            _ => false,
                        };
                        // Retry using a different origin
                        let origin = if !is_mandatory && none_can_call(&extrinsic) { Some(RuntimeOrigin::none()) } else { None };
                        if let Some(origin) = origin {
                            log::debug!(target: "fuzz::result", "    result:     {}", match &res {
                                Ok(x) => {
                                    if let Some(w) = x.actual_weight {
                                        format!("Ok {{ actual_weight: {:?} }}", w)
                                    } else {
                                        format!("Ok {{ }}")
                                    }
                                }
                                Err(e) => {
                                    if let Some(w) = e.post_info.actual_weight {
                                        format!("Err {{ error: {:?}, actual_weight: {:?} }}", e.error, w)
                                    } else {
                                        format!("Err {{ error: {:?} }}", e.error)
                                    }
                                }
                            });

                            //log::debug!(target: "fuzz::origin", "\n    origin:     {origin:?}");
                            //log::debug!(target: "fuzz::call", "    call:       {extrinsic:?}");

                            let res2 = extrinsic.clone().dispatch(origin);
                            if let Ok(_) = res2 {
                                panic!("none origin was able to call an extrinsic");
                            }
                        }
                    }

                    log::debug!(target: "fuzz::result", "    result:     {}", match &res {
                        Ok(x) => {
                            if let Some(w) = x.actual_weight {
                                format!("Ok {{ actual_weight: {:?} }}", w)
                            } else {
                                format!("Ok {{ }}")
                            }
                        }
                        Err(e) => {
                            if let Some(w) = e.post_info.actual_weight {
                                format!("Err {{ error: {:?}, actual_weight: {:?} }}", e.error, w)
                            } else {
                                format!("Err {{ error: {:?} }}", e.error)
                            }
                        }
                    });
                }
                ExtrOrPseudo::Pseudo(fuzz_call) => {
                    match fuzz_call {
                        FuzzRuntimeCall::SetOrigin {
                            origin: new_origin, retry_as_root, try_root_first
                        } => {
                            origin = new_origin;
                            origin_retry_as_root = retry_as_root;
                            origin_try_root_first = try_root_first;
                        }
                        // Set relay data and start a new block
                        FuzzRuntimeCall::SetRelayData(x) => {
                            // Disabled
                            continue;
                        }
                        FuzzRuntimeCall::CallRuntimeApi(x) => {
                            // Disabled because anything related to block building will panic
                            continue;
                        }
                        FuzzRuntimeCall::RecvEthMsg(x) => {
                            // Unimplemented
                            continue;
                        }
                    }
                }
            }
        }

        // For testing, disable this to check performance
        /*
        finalize_block(elapsed);
        check_invariants(block, initial_total_issuance, block_rewards.get());
         */
        let events_all = dancelight_runtime::System::events();
        let (_, events) = events_all.split_at(num_events_before);
        use std::hash::{BuildHasherDefault, DefaultHasher};
        static SEEN_EVENTS: Mutex<HashSet<(u8, u8), BuildHasherDefault<DefaultHasher>>> = Mutex::new(HashSet::with_hasher(BuildHasherDefault::new()));
        let mut events: Vec<_> = events.iter().map(|ev| {
            &ev.event
        }).collect();
        let mut seen_events = SEEN_EVENTS.lock().unwrap();
        events.retain(|x| {
            let x_enc = x.encode();
            let first_2_bytes = (x_enc[0], x_enc[1]);

            // Keep events that do not appear in the hashset
            let keep = !seen_events.contains(&first_2_bytes);

            // Insert new events
            seen_events.insert(first_2_bytes);

            keep
        });
        drop(seen_events);
        // TODO: disable write to file if running this in multithreaded mode (-j4)
        let mut tmp_events = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open("/tmp/fuzz_events.txt").expect("failed to open /tmp/fuzz_events.txt");
        for event in events {
            let x_enc = event.encode();
            let first_2_bytes = (x_enc[0], x_enc[1]);
            log::info!(target: "fuzz::events", "{:03?} {:?}", first_2_bytes, event);
            use std::io::Write;
            writeln!(tmp_events, "{:03?} {:?}", first_2_bytes, event);
        }
        // Assert that it is not possible to mint tokens using the allowed extrinsics
        let final_total_issuance = TotalIssuance::<Runtime>::get();
        // Some extrinsics burn tokens so final issuance can be lower
        assert!(initial_total_issuance >= final_total_issuance, "{} >= {}", initial_total_issuance, final_total_issuance);
    });
}

fn fuzz_init() {
    // Uncomment to init logger
    init_logger();

    // Initialize genesis storage
    &*GENESIS_STORAGE;
}

libfuzzer_sys::fuzz_target!(init: fuzz_init(), |data: &[u8]| fuzz_main(data));

fn extrinsics_iter(mut extrinsic_data: &[u8]) -> impl Iterator<Item = ExtrOrPseudo> + use<'_> {
    iter::from_fn(move || DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
}

struct CursorOutputIgnoreErrors<W>(std::io::Cursor<W>);
impl<W: std::io::Write> parity_scale_codec::Output for CursorOutputIgnoreErrors<W>
where std::io::Cursor<W>: std::io::Write,
{
    fn write(&mut self, bytes: &[u8]) {
        // Ignore errors
        let _ = self.0.write_all(bytes);
    }
}

fn fuzz_crossover_extr_or_pseudo(data1: &[u8], data2: &[u8], out: &mut [u8], _seed: u32) -> usize {
    // Decode from 1
    let extr1 = extrinsics_iter(data1);
    // Decode from 2
    let extr2 = extrinsics_iter(data2);
    // Encode each item, first all from 1 then all from 2
    let mut out_writer = CursorOutputIgnoreErrors(std::io::Cursor::new(out));
    for extr in extr1.chain(extr2) {
        extr.encode_to(&mut out_writer);
        if out_writer.0.position() as usize == out_writer.0.get_ref().len() {
            break;
        }
    }

    out_writer.0.position() as usize
}
libfuzzer_sys::fuzz_crossover!(|data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32| { fuzz_crossover_extr_or_pseudo(data1, data2, out, seed) });

/*
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
*/
