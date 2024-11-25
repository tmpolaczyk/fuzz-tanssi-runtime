#![no_main]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Tanssi Runtime fuzz target. Generates random extrinsics and some pseudo-extrinsics.
//!
//! Based on https://github.com/srlabs/substrate-runtime-fuzzer/blob/2a42a8b750aff0e12eb0e09b33aea9825a40595a/runtimes/kusama/src/main.rs

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
    primitives::{vstaging::SchedulerParams, ValidationCode},
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
    let authority_keys = get_authority_keys_from_seed(&account.to_string(), None);

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

fn check_invariants(block: u32, initial_total_issuance: Balance) {
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
    /*
    let total_issuance = TotalIssuance::<Runtime>::get();
    let counted_issuance = counted_free + counted_reserved;
    assert!(
        total_issuance == counted_issuance,
        "Inconsistent total issuance: {total_issuance} but counted {counted_issuance}"
    );
    assert!(
        total_issuance <= initial_total_issuance,
        "Total issuance {total_issuance} greater than initial issuance {initial_total_issuance}"
    );
    */
    // We run all developer-defined integrity tests
    AllPalletsWithSystem::integrity_test();
    AllPalletsWithSystem::try_state(block, TryStateSelect::All).unwrap();
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

        const EXPORTED_STATE_CHAIN_SPEC_JSON: &[u8] = include_bytes!("../dancelight--2024-11-21.json");

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

lazy_static::lazy_static! {
    static ref LOGGER: () = init_logger();
}

fn fuzz_main(data: &[u8]) {
    // Uncomment to init logger
    *LOGGER;
    //println!("data: {:?}", data);
    let mut extrinsic_data = data;
    //#[allow(deprecated)]
    let extrinsics: Vec<(/* lapse */ u8, /* origin */ u8, ExtrOrPseudo)> =
        iter::from_fn(|| DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
        .filter(|(_, _, x)| match x {
            ExtrOrPseudo::Extr(x) => !recursively_find_call(x.clone(), |call| {
                // We filter out calls with Fungible(0) as they cause a debug crash
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
                || matches!(call.clone(), RuntimeCall::System(_))
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

    let initialize_block = |block: u32| {
        log::debug!(target: "fuzz::initialize", "\ninitializing block {block}");

        let pre_digest = Digest {
            logs: vec![DigestItem::PreRuntime(
                BABE_ENGINE_ID,
                PreDigest::SecondaryPlain(SecondaryPlainPreDigest {
                    slot: Slot::from(u64::from(block + 333333333)),
                    authority_index: 0,
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

        Executive::initialize_block(&parent_header);

        Timestamp::set(RuntimeOrigin::none(), u64::from(block) * SLOT_DURATION + 2_000_000_000_000).unwrap();

        Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(RuntimeCall::AuthorNoting(
            pallet_author_noting::Call::set_latest_author_data { data: () },
        )))
        .unwrap()
        .unwrap();

        ParaInherent::enter(
            RuntimeOrigin::none(),
            primitives::InherentData {
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
    let (storage, root, shared_cache) = &*GENESIS_STORAGE;
    let root = *root;
    let cache = shared_cache.local_cache();
    let backend: TrieBackend<_, BlakeTwo256> = TrieBackendBuilder::new_with_cache(storage, root, cache).build();
    let extensions = None;
    let mut ext = Ext::new(&mut overlay, &backend, extensions);
    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        let initial_total_issuance = TotalIssuance::<Runtime>::get();

        initialize_block(block);

        for (lapse, origin, extrinsic) in extrinsics {
            if lapse > 0 {
                finalize_block(elapsed);

                block += u32::from(lapse) * 393; // 393 * 256 = 100608 which nearly corresponds to a week
                weight = 0.into();
                elapsed = Duration::ZERO;

                initialize_block(block);
            }

            match extrinsic {
                ExtrOrPseudo::Extr(extrinsic) => {
                    weight.saturating_accrue(extrinsic.get_dispatch_info().weight);
                    if weight.ref_time() >= 2 * WEIGHT_REF_TIME_PER_SECOND {
                        log::warn!("Extrinsic would exhaust block weight, skipping");
                        continue;
                    }

                    let origin = if origin == 0 {
                        // Check if this extrinsic can be called by root, if not return a Signed origin
                        if root_can_call(&extrinsic) {
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
                    let res = extrinsic.clone().dispatch(origin);
                    elapsed += now.elapsed();

                    log::debug!(target: "fuzz::result", "    result:     {res:?}");
                }
                ExtrOrPseudo::Pseudo(fuzz_call) => {
                    match fuzz_call {
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

        finalize_block(elapsed);

        check_invariants(block, initial_total_issuance);
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
