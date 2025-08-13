#![no_main]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Tanssi Runtime fuzz target. Generates random extrinsics and some pseudo-extrinsics.
//!
//! Based on https://github.com/srlabs/substrate-runtime-fuzzer/blob/2a42a8b750aff0e12eb0e09b33aea9825a40595a/runtimes/kusama/src/main.rs

use crate::create_storage::create_storage;
use crate::create_storage::ext_to_simple_storage;
use crate::genesis::invulnerables_from_seeds;
use crate::metadata::{
    ACCOUNT_ID_TYPE_ID, METADATA, RUNTIME_CALL_TYPE_ID, call_name_from_idx, event_name_from_idx,
};
use crate::simple_backend::SimpleBackend;
use crate::storage_tracer::{BlockContext, ExtStorageTracer, TracingExt};
use crate::without_storage_root::WithoutStorageRoot;
use dancelight_runtime::{Session, System};
use frame_support::dispatch::DispatchResultWithPostInfo;
use frame_support::traits::CallerTrait;
use itertools::{EitherOrBoth, Itertools};
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use sp_externalities::Externalities;
use sp_state_machine::OverlayedChanges;
use std::sync::Mutex;
use {
    dancelight_runtime::{
        AccountId, AllPalletsWithSystem, Balance, Balances, CollatorsInflationRatePerBlock,
        ContainerRegistrar, Executive, ExternalValidators, Header, MultiBlockMigrations,
        ParaInherent, Runtime, RuntimeCall, RuntimeOrigin, Timestamp, UncheckedExtrinsic,
        ValidatorsInflationRatePerEra,
    },
    dancelight_runtime_constants::time::SLOT_DURATION,
    frame_support::{
        dispatch::{CallableCallFor as CallableCallForG, GetDispatchInfo},
        pallet_prelude::Weight,
        storage::unhashed,
        traits::{IntegrityTest, OriginTrait, TryState, TryStateSelect},
        weights::constants::WEIGHT_REF_TIME_PER_SECOND,
    },
    frame_system::Account,
    pallet_balances::{Holds, TotalIssuance},
    parity_scale_codec::{DecodeLimit, Encode},
    rand::{Rng, SeedableRng, seq::IndexedRandom},
    scale_info::TypeInfo,
    scale_value::{Composite, ValueDef},
    sp_consensus_aura::Slot,
    sp_consensus_babe::{
        BABE_ENGINE_ID,
        digests::{PreDigest, SecondaryPlainPreDigest},
    },
    sp_core::{Decode, H256},
    sp_runtime::{
        Digest, DigestItem, DispatchError, Storage,
        traits::{BlakeTwo256, Dispatchable, Header as HeaderT},
    },
    sp_state_machine::{Ext, LayoutV1, MemoryDB, TrieBackend, TrieBackendBuilder},
    sp_storage::StateVersion,
    sp_trie::{
        GenericMemoryDB,
        cache::{CacheSize, SharedTrieCache},
    },
    std::{
        collections::BTreeMap,
        io::Write,
        iter,
        sync::{Arc, atomic::AtomicBool},
        time::{Duration, Instant},
    },
};

mod create_storage;
mod event_tracer;
mod extr_tracer;
mod genesis;
mod metadata;
mod mutators;
mod read_snapshot;
mod without_storage_root;
// TODO: extract to separate crate to speed up compilation
mod simple_backend;
mod storage_tracer;

use crate::event_tracer::EventTracer;
use crate::extr_tracer::ExtrTracer;
pub use storage_tracer::StorageTracer;

type CallableCallFor<A, R = Runtime> = CallableCallForG<A, R>;

fn recursively_find_call(call: &RuntimeCall, matches_on: fn(&RuntimeCall) -> bool) -> bool {
    if let RuntimeCall::Utility(
        CallableCallFor::<dancelight_runtime::Utility>::batch { calls }
        | CallableCallFor::<dancelight_runtime::Utility>::force_batch { calls }
        | CallableCallFor::<dancelight_runtime::Utility>::batch_all { calls },
    ) = call
    {
        for call in calls {
            if recursively_find_call(call, matches_on) {
                return true;
            }
        }
    } else if let RuntimeCall::Multisig(
        CallableCallFor::<dancelight_runtime::Multisig>::as_multi_threshold_1 { call, .. },
    )
    | RuntimeCall::Utility(
        CallableCallFor::<dancelight_runtime::Utility>::as_derivative { call, .. },
    )
    | RuntimeCall::Proxy(CallableCallFor::<dancelight_runtime::Proxy>::proxy {
        call,
        ..
    }) = call
    {
        return recursively_find_call(call, matches_on);
    } else if matches_on(call) {
        return true;
    }
    false
}

/// Return true if the root origin can execute this extrinsic.
/// Any extrinsic that could brick the chain should be disabled, we only want to test real-world scenarios.
fn root_can_call(call: &RuntimeCall) -> bool {
    // TODO: for storage tracing fuzz_live_oneblock: disable root extrinsics
    //return false;
    match call {
        // Allow root to call any pallet_registrar extrinsic, as it is unlikely to brick the chain
        // TODO: except register(1000), because that may actually break some things
        RuntimeCall::ContainerRegistrar(..) => true,
        // TODO: enable relay chain registrar?
        RuntimeCall::Registrar(..) => false,
        // Allow root to call pallet_author_noting killAuthorData
        RuntimeCall::AuthorNoting(CallableCallFor::<dancelight_runtime::AuthorNoting>::kill_author_data {
            ..
        }) => true,
        // Allow root to change configuration, except using set_bypass_consistency_check
        RuntimeCall::CollatorConfiguration(call_configuration) => {
            if let CallableCallFor::<dancelight_runtime::CollatorConfiguration>::set_bypass_consistency_check { .. } =
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
        // Allow entering maintenance mode, shouldnt break anything
        RuntimeCall::MaintenanceMode(x) => true,
        // Allow enable and disable inactivity tracking
        RuntimeCall::InactivityTracking(x) => true,
        // Some ethereum pallets, also shouldnt break anything
        RuntimeCall::EthereumBeaconClient(x) => true,
        RuntimeCall::EthereumOutboundQueue(x) => true,
        RuntimeCall::EthereumInboundQueue(x) => true,
        RuntimeCall::EthereumSystem(x) => match x {
            /*
            Overflow when casting to u128:
            [Extr(RuntimeCall::EthereumSystem(Call::set_pricing_parameters { params: PricingParameters { exchange_rate: FixedU128(49374304219900875090.764158725393818943), rewards: Rewards { local: 49374304219900874850019441219996034341, remote: 233163559363069177235500382025972612914986316744954254533925 }, fee_per_gas: 16801205105022349924204417432633147414003880127955689684156590579914555523072, multiplier: FixedU128(49374304219900875090.764158725393818917) } }))]
             */
            CallableCallFor::<dancelight_runtime::EthereumSystem>::set_pricing_parameters { .. } => false,
            _ => true,
        },
        RuntimeCall::EthereumTokenTransfers(x) => true,
        RuntimeCall::ForeignAssetsCreator(x) => true,
        RuntimeCall::ForeignAssets(x) => true,
        RuntimeCall::Beefy(x) => true,
        _ => false,
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

fn get_origin(origin: usize) -> &'static AccountId {
    &VALID_ORIGINS[origin % VALID_ORIGINS.len()]
}

fn genesis_storage_from_snapshot() -> (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
    const EXPORTED_STATE_CHAIN_SPEC_JSON: &[u8] =
        include_bytes!("../../../snapshots/dancelight-2025-08-12.json");

    read_snapshot::read_snapshot(EXPORTED_STATE_CHAIN_SPEC_JSON)
}

// Creating a genesis state from scratch is hard so we just use the raw specs from zombienet as a
// "local" network.
fn genesis_storage_from_zombienet() -> (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
    const ZOMBIENET_STATE_CHAIN_SPEC_JSON: &[u8] = include_bytes!(
        "../../../snapshots/zombienet-dancelight-a1f0612013506d77c22e2afb87a56b447e603572-before-oninitialize.json"
    );

    read_snapshot::read_snapshot(ZOMBIENET_STATE_CHAIN_SPEC_JSON)
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
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
pub enum FuzzRuntimeCall {
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
    // New block
    NewBlock,
    // Fast forward to next session
    NewSession,
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
pub enum ExtrOrPseudo {
    Extr(RuntimeCall),
    Pseudo(FuzzRuntimeCall),
}

// Attempt to panic on this error log
/*
2025-08-05 11:39:45 Post dispatch weight is greater than pre dispatch weight. Pre dispatch weight may underestimating the actual weight. Greater post dispatch weight components are ignored.
                    Pre dispatch weight: Weight { ref_time: 3097114602, proof_size: 276453 },
                    Post dispatch weight: Weight { ref_time: 3099021404, proof_size: 276453 }
*/

struct PanicOnError;

impl Log for PanicOnError {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // we only care about Error (you can broaden this if you like)
        metadata.level() == Level::Error
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // panic immediately when any crate does `log::error!(…)`
            panic!("logged error: {}", record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: PanicOnError = PanicOnError;

fn init_panic_logger() -> Result<(), SetLoggerError> {
    // install our logger as the one-and-only global logger
    log::set_logger(&LOGGER)?;
    // we only need Error-level records (the .log() above ignores everything else)
    log::set_max_level(LevelFilter::Error);
    Ok(())
}

pub fn init_logger() {
    // If you want to find a test case to reproduce an error log, use this logger instead
    //init_panic_logger().unwrap();
    //return;
    use sc_tracing::logging::LoggerBuilder;
    let env_rust_log = std::env::var("RUST_LOG");
    // No logs by default
    let mut logger = LoggerBuilder::new(env_rust_log.unwrap_or("".to_string()));
    logger.with_log_reloading(false).with_detailed_output(false);

    logger.init().unwrap();
}

const NEED_TO_EXPORT_STORAGE: bool = false;
static EXPORTED_STORAGE: AtomicBool = AtomicBool::new(false);
static FUZZ_MAIN_CALLED: AtomicBool = AtomicBool::new(false);
static FUZZ_INIT_CALLED: AtomicBool = AtomicBool::new(false);

pub trait FuzzerConfig {
    // Making this generic to try to support the same trait in different runtimes
    type ExtrOrPseudo;
    type ExternalitiesParts;
    type Ext<'a>: Externalities;

    fn genesis_storage() -> &'static (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>);
    fn genesis_storage_simple() -> &'static Storage;

    fn extrinsics_filter(x: &Self::ExtrOrPseudo) -> bool;

    fn externalities_parts() -> Self::ExternalitiesParts;
    fn ext_new(parts: &mut Self::ExternalitiesParts) -> Self::Ext<'_>;
    fn after_each_extr(
        extrinsic: &RuntimeCall,
        num_events_before: &mut usize,
        extr_ok: bool,
        is_root: bool,
    ) {
    }
    fn after_all(ext: Self::Ext<'_>) {}
}

pub struct TraceStorage<FC: FuzzerConfig>(FC);

lazy_static::lazy_static! {
    pub static ref STORAGE_TRACER: Arc<Mutex<StorageTracer>> = {
        Arc::new(Mutex::new(StorageTracer::default()))
    };
    pub static ref EVENT_TRACER: Arc<Mutex<EventTracer>> = {
        Arc::new(Mutex::new(EventTracer::default()))
    };
    pub static ref EXTR_TRACER: Arc<Mutex<ExtrTracer>> = {
        Arc::new(Mutex::new(ExtrTracer::default()))
    };
}

impl<FC: FuzzerConfig> FuzzerConfig for TraceStorage<FC> {
    type ExtrOrPseudo = FC::ExtrOrPseudo;
    type ExternalitiesParts = FC::ExternalitiesParts;
    type Ext<'a> = TracingExt<FC::Ext<'a>>;

    fn genesis_storage() -> &'static (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
        FC::genesis_storage()
    }

    fn genesis_storage_simple() -> &'static Storage {
        FC::genesis_storage_simple()
    }

    fn extrinsics_filter(x: &Self::ExtrOrPseudo) -> bool {
        FC::extrinsics_filter(x)
    }

    fn externalities_parts() -> Self::ExternalitiesParts {
        FC::externalities_parts()
    }

    fn ext_new(parts: &mut Self::ExternalitiesParts) -> Self::Ext<'_> {
        let ext = FC::ext_new(parts);
        TracingExt::new(ext)
    }
    fn after_each_extr(
        extrinsic: &RuntimeCall,
        num_events_before: &mut usize,
        extr_ok: bool,
        is_root: bool,
    ) {
        FC::after_each_extr(extrinsic, num_events_before, extr_ok, is_root)
    }
    fn after_all(ext: Self::Ext<'_>) {
        let mut storage_tracer = STORAGE_TRACER.lock().unwrap();
        storage_tracer.update_histograms(&ext.tracer);

        FC::after_all(ext.into_inner())
    }
}

pub struct TraceEvents<FC: FuzzerConfig>(FC);

impl<FC: FuzzerConfig> FuzzerConfig for TraceEvents<FC> {
    type ExtrOrPseudo = FC::ExtrOrPseudo;
    type ExternalitiesParts = FC::ExternalitiesParts;
    type Ext<'a> = TracingExt<FC::Ext<'a>>;

    fn genesis_storage() -> &'static (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
        FC::genesis_storage()
    }

    fn genesis_storage_simple() -> &'static Storage {
        FC::genesis_storage_simple()
    }

    fn extrinsics_filter(x: &Self::ExtrOrPseudo) -> bool {
        FC::extrinsics_filter(x)
    }

    fn externalities_parts() -> Self::ExternalitiesParts {
        FC::externalities_parts()
    }

    fn ext_new(parts: &mut Self::ExternalitiesParts) -> Self::Ext<'_> {
        let ext = FC::ext_new(parts);
        TracingExt::new(ext)
    }
    fn after_each_extr(
        extrinsic: &RuntimeCall,
        num_events_before: &mut usize,
        extr_ok: bool,
        is_root: bool,
    ) {
        let events_all = System::events();
        let (_, events) = events_all.split_at(*num_events_before);

        if extr_ok == false {
            // Extrinsics are transactional, so if the extr returned an error, it could not have
            // emitted any events
            assert!(events.is_empty(), "{:?}", events);
            // So nothing to update here
            return;
        }
        let events: Vec<_> = events.iter().map(|ev| &ev.event).collect();

        {
            let mut event_tracer = EVENT_TRACER.lock().unwrap();
            for event in events {
                let x_enc = event.encode();
                let first_2_bytes = (x_enc[0], x_enc[1]);
                event_tracer.insert(first_2_bytes, is_root, || {
                    let evn_name = event_name_from_idx(first_2_bytes);
                    //format!("{} {} {:?}", evn_name.0, evn_name.1, event)
                    format!("{} {}", evn_name.0, evn_name.1)
                });
            }
        }

        *num_events_before = events_all.len();

        if extr_ok {
            let x_enc = extrinsic.encode();
            let first_2_bytes = (x_enc[0], x_enc[1]);
            let mut ok_extrinsics = EXTR_TRACER.lock().unwrap();
            ok_extrinsics.insert(first_2_bytes, is_root, || {
                let evn_name = call_name_from_idx(first_2_bytes);
                //format!("{} {} {:?}", evn_name.0, evn_name.1, event)
                format!("{} {}", evn_name.0, evn_name.1)
            });
        }

        FC::after_each_extr(extrinsic, num_events_before, extr_ok, is_root)
    }
    fn after_all(ext: Self::Ext<'_>) {
        FC::after_all(ext.into_inner())
    }
}

pub struct FuzzLiveOneblock;

impl FuzzerConfig for FuzzLiveOneblock {
    type ExtrOrPseudo = ExtrOrPseudo;
    type ExternalitiesParts = (
        OverlayedChanges<BlakeTwo256>,
        SimpleBackend,
        Option<sp_externalities::Extensions>,
    );
    type Ext<'a> = WithoutStorageRoot<Ext<'a, BlakeTwo256, SimpleBackend>>;

    fn genesis_storage() -> &'static (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
        lazy_static::lazy_static! {
            static ref GENESIS_STORAGE: (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) = {
                genesis_storage_from_snapshot()
            };
        }
        &*GENESIS_STORAGE
    }
    // TODO: caching Storage is useless because BasicExternalities needs a clone of the entire Storage
    // And trying to cache BasicExternalities directly doesn't work because there is a RefCell somewhere
    // maybe using thread_local and unsafe ref to ref mut its doable, but not sure
    fn genesis_storage_simple() -> &'static Storage {
        lazy_static::lazy_static! {
            static ref GENESIS_STORAGE: Storage = {
                use sp_runtime::traits::BlakeTwo256;
                use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
                let mut overlay = OverlayedChanges::default();
                let (storage, root, shared_cache) = FuzzLiveOneblock::genesis_storage();
                let root = *root;
                let cache = shared_cache.local_cache();
                let mut backend: TrieBackend<_, BlakeTwo256> =
                    TrieBackendBuilder::new_with_cache(storage, root, cache).build();
                let extensions = None;
                let mut ext = Ext::new(&mut overlay, &backend, extensions);

                ext_to_simple_storage(&mut ext)
            };
        }
        &*GENESIS_STORAGE
    }

    fn extrinsics_filter(x: &Self::ExtrOrPseudo) -> bool {
        default_extrinsics_filter(x)
    }

    fn externalities_parts() -> Self::ExternalitiesParts {
        use sp_runtime::traits::BlakeTwo256;
        use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
        let mut overlay = OverlayedChanges::<BlakeTwo256>::default();
        let (storage, root, shared_cache) = Self::genesis_storage();
        let root = *root;
        let cache = shared_cache.local_cache();
        //let mut backend: TrieBackend<_, BlakeTwo256> =
        //    TrieBackendBuilder::new_with_cache(storage, root, cache).build();
        let backend = SimpleBackend::new(Self::genesis_storage_simple());
        let extensions = None;

        (overlay, backend, extensions)
    }

    fn ext_new(parts: &mut Self::ExternalitiesParts) -> Self::Ext<'_> {
        let mut ext = Ext::new(&mut parts.0, &parts.1, parts.2.as_mut());
        // Not needed here because we never finalize the block
        let mut ext = WithoutStorageRoot::new(ext);

        ext
    }
}

pub struct FuzzZombie;

impl FuzzerConfig for FuzzZombie {
    type ExtrOrPseudo = ExtrOrPseudo;
    type ExternalitiesParts = (
        OverlayedChanges<BlakeTwo256>,
        SimpleBackend,
        Option<sp_externalities::Extensions>,
    );
    type Ext<'a> = WithoutStorageRoot<Ext<'a, BlakeTwo256, SimpleBackend>>;

    fn genesis_storage() -> &'static (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
        lazy_static::lazy_static! {
            static ref GENESIS_STORAGE: (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) = {
                genesis_storage_from_zombienet()
            };
        }
        &*GENESIS_STORAGE
    }
    fn genesis_storage_simple() -> &'static Storage {
        lazy_static::lazy_static! {
            static ref GENESIS_STORAGE: Storage = {
                use sp_runtime::traits::BlakeTwo256;
                use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
                let mut overlay = OverlayedChanges::default();
                let (storage, root, shared_cache) = FuzzZombie::genesis_storage();
                let root = *root;
                let cache = shared_cache.local_cache();
                let mut backend: TrieBackend<_, BlakeTwo256> =
                    TrieBackendBuilder::new_with_cache(storage, root, cache).build();
                let extensions = None;
                let mut ext = Ext::new(&mut overlay, &backend, extensions);

                ext_to_simple_storage(&mut ext)
            };
        }
        &*GENESIS_STORAGE
    }
    fn extrinsics_filter(x: &Self::ExtrOrPseudo) -> bool {
        default_extrinsics_filter(x)
    }
    fn externalities_parts() -> Self::ExternalitiesParts {
        use sp_runtime::traits::BlakeTwo256;
        use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
        let mut overlay = OverlayedChanges::<BlakeTwo256>::default();
        let (storage, root, shared_cache) = Self::genesis_storage();
        let root = *root;
        let cache = shared_cache.local_cache();
        //let mut backend: TrieBackend<_, BlakeTwo256> =
        //    TrieBackendBuilder::new_with_cache(storage, root, cache).build();
        let backend = SimpleBackend::new(Self::genesis_storage_simple());
        let extensions = None;

        (overlay, backend, extensions)
    }

    fn ext_new(parts: &mut Self::ExternalitiesParts) -> Self::Ext<'_> {
        let mut ext = Ext::new(&mut parts.0, &parts.1, parts.2.as_mut());
        // Not needed here because we never finalize the block
        let mut ext = WithoutStorageRoot::new(ext);

        ext
    }
}

/// Some `RuntimeCall`s have known issues. We ignore them in the fuzzer.
/// For instance, `pallet_sudo` should be disabled because we don't want to
/// test a signed origin executing root stuff.
/// Same for `pallet_referenda` if the proposal origin is root.
pub fn is_disabled_call(x: &RuntimeCall) -> bool {
    recursively_find_call(x, |call| {
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
                RuntimeCall::Referenda(CallableCallFor::<dancelight_runtime::Referenda>::submit {
                    proposal_origin: matching_origin,
                    ..
                }) if RuntimeOrigin::from(*matching_origin.clone()).caller().is_root()
            )
    })
}

/// Returns true for calls we want to keep in the fuzzer.
/// Returns false for calls that are disabled in this fuzzer.
pub fn default_extrinsics_filter(x: &ExtrOrPseudo) -> bool {
    match x {
        ExtrOrPseudo::Extr(x) => !is_disabled_call(x),
        ExtrOrPseudo::Pseudo(x) => true,
    }
}

pub struct BlockState {
    block: u32,
    slot: u64,
    weight: Weight,
    elapsed: Duration,
    block_rewards: u128,
    last_era: u32,
    num_created_blocks: u32,
}

impl BlockState {
    pub fn initial() -> Self {
        Self {
            block: 1,
            slot: 1,
            weight: Weight::zero(),
            elapsed: Duration::ZERO,
            block_rewards: 0,
            last_era: 0,
            num_created_blocks: 0,
        }
    }
}

pub fn initialize_block(state: &mut BlockState) {
    state.block += 1;
    state.num_created_blocks += 1;
    state.weight = Weight::zero();
    state.elapsed = Duration::ZERO;

    log::debug!(target: "fuzz::initialize", "\ninitializing block {}", state.block);

    ExtStorageTracer::set_block_context(BlockContext::OnInitialize);

    let validators = dancelight_runtime::Session::validators();
    let authority_index =
        u32::try_from(u64::from(state.slot) % u64::try_from(validators.len()).unwrap()).unwrap();
    let pre_digest = Digest {
        logs: vec![DigestItem::PreRuntime(
            BABE_ENGINE_ID,
            PreDigest::SecondaryPlain(SecondaryPlainPreDigest {
                slot: Slot::from(state.slot),
                authority_index,
            })
            .encode(),
        )],
    };

    let grandparent_header = Header::new(
        state.block,
        H256::default(),
        H256::default(),
        <frame_system::Pallet<Runtime>>::parent_hash(),
        pre_digest.clone(),
    );

    let parent_header = Header::new(
        state.block,
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
            state.block_rewards += new_supply_inflation_rewards;
        }

        if state.last_era == 0 {
            let era_index = ExternalValidators::current_era().unwrap();
            state.last_era = era_index;
        }
        let era_index = ExternalValidators::current_era().unwrap();
        let mut new_era = false;
        if era_index > state.last_era {
            new_era = true;
        }
        if new_era {
            let new_supply_validators =
                ValidatorsInflationRatePerEra::get() * Balances::total_issuance();
            state.block_rewards += new_supply_validators;
        }
    }

    Executive::initialize_block(&parent_header);

    ExtStorageTracer::set_block_context(BlockContext::Inherents);

    Timestamp::set(RuntimeOrigin::none(), state.slot * SLOT_DURATION).unwrap();
    state.slot += 1;

    Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(RuntimeCall::AuthorNoting(
        CallableCallFor::<dancelight_runtime::AuthorNoting>::set_latest_author_data { data: () },
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
}

pub fn finalize_block(state: &mut BlockState) {
    log::debug!(target: "fuzz::time", "\n  time spent: {:?}", state.elapsed);
    assert!(
        state.elapsed.as_secs() <= 2,
        "block execution took too much time"
    );

    log::debug!(target: "fuzz::finalize", "  finalizing block");
    ExtStorageTracer::set_block_context(BlockContext::OnFinalize);

    Executive::finalize_block();
}

pub struct OriginStateMachine {
    origin: u8,
    retry_as_root: bool,
    try_root_first: bool,
}

impl OriginStateMachine {
    pub fn new() -> Self {
        Self {
            origin: 0,
            retry_as_root: true,
            try_root_first: false,
        }
    }

    pub fn first_origin(&self, extrinsic: &RuntimeCall) -> RuntimeOrigin {
        // Check if this extrinsic can be called by root, if not return a Signed origin
        let origin = if self.try_root_first && root_can_call(extrinsic) {
            RuntimeOrigin::root()
        } else {
            RuntimeOrigin::signed(get_origin(self.origin.into()).clone())
        };

        origin
    }

    pub fn second_origin(&self, extrinsic: &RuntimeCall) -> Option<RuntimeOrigin> {
        if self.retry_as_root == false {
            None
        } else if !root_can_call(extrinsic) {
            // If root cannot call this extrinsic, only signed origin is valid, so no need to try 2 origins
            None
        } else {
            if self.try_root_first {
                // we already tried root, now try signed origin
                Some(RuntimeOrigin::signed(
                    get_origin(self.origin.into()).clone(),
                ))
            } else {
                // now try root
                Some(RuntimeOrigin::root())
            }
        }
    }

    pub fn get_origins(&self, extrinsic: &RuntimeCall) -> impl Iterator<Item = RuntimeOrigin> {
        std::iter::once(self.first_origin(extrinsic))
            .chain(std::iter::once_with(|| self.second_origin(extrinsic)).flatten())
    }
}

pub fn format_dispatch_result(res: &DispatchResultWithPostInfo) -> String {
    match res {
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
    }
}

/// Start fuzzing a snapshot of a live network.
/// This doesn't run `on_initialize` and `on_finalize`, everything is executed inside the same block.
/// Inherents are also not tested, the snapshot is created after the inherents.
pub fn fuzz_live_oneblock<FC: FuzzerConfig<ExtrOrPseudo = ExtrOrPseudo>>(data: &[u8]) {
    FUZZ_MAIN_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
    //println!("data: {:?}", data);
    let mut extrinsic_data = data;
    //#[allow(deprecated)]
    let mut extrinsics: Vec<ExtrOrPseudo> =
        iter::from_fn(|| DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
            .filter(FC::extrinsics_filter)
            .collect();

    if extrinsics.iter().all(|x| match x {
        ExtrOrPseudo::Extr(_) => false,
        ExtrOrPseudo::Pseudo(_) => true,
    }) {
        // empty extrinsics or all extrinsics pseudo: do not test
        return;
    }

    //println!("{:?}", extrinsics);

    let mut elapsed = Duration::ZERO;

    let mut ext_parts = FC::externalities_parts();
    let mut ext = FC::ext_new(&mut ext_parts);

    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        // The snapshot is saved after the initial on_initialize
        //initialize_block(block);

        // Use lazy_static to cache values that don't depend on fuzzer input
        lazy_static::lazy_static! {
            static ref INITIAL_TOTAL_ISSUANCE: Balance = TotalIssuance::<Runtime>::get();
            static ref NUM_EVENTS_BEFORE: usize = System::events().len();
        }
        let initial_total_issuance = *INITIAL_TOTAL_ISSUANCE;
        let num_events_before = *NUM_EVENTS_BEFORE;
        let mut num_events_before_inner = *NUM_EVENTS_BEFORE;

        // Origin is kind of like a state machine
        // By default we try using Alice, and if we get Err::BadOrigin, we check if root_can_call
        // that extrinsic, and if so retry as root
        let mut origin_sm = OriginStateMachine::new();

        //let mut seen_values = SeenValues::default();
        //test_mutate(&mut extrinsics, &mut seen_values);

        for extrinsic in extrinsics {
            match extrinsic {
                ExtrOrPseudo::Extr(extrinsic) => {
                    let eww = extrinsic.get_dispatch_info();
                    if eww.call_weight.ref_time() + eww.extension_weight.ref_time()
                        >= 2 * WEIGHT_REF_TIME_PER_SECOND
                    {
                        // This extrinsic weight is greater than the allowed block weight.
                        // This is normal, it can happen for:
                        // * Disabled extrinsics. When an extrinsic benchmark fails, its weight is set
                        //   to a high value to effectively disable it.
                        // * High input params. Some extrinsics have a weight that depends on some
                        //   input. If we set that input to u32::MAX, the weight will also probably be
                        //   u32::MAX. So we ignore this call.
                        //log::warn!("Extrinsic would exhaust block weight, skipping");
                        continue;
                    }

                    let mut extr_ok = false;
                    let mut is_root = false;
                    for origin in origin_sm.get_origins(&extrinsic) {
                        log::debug!(target: "fuzz::origin", "\n    origin:     {origin:?}");
                        log::debug!(target: "fuzz::call", "    call:       {extrinsic:?}");

                        if origin.caller.is_root() {
                            is_root = true;
                            ExtStorageTracer::set_block_context(BlockContext::ExtrinsicRoot);
                        } else {
                            is_root = false;
                            ExtStorageTracer::set_block_context(BlockContext::ExtrinsicSigned);
                        }

                        let now = Instant::now(); // We get the current time for timing purposes.
                        #[allow(unused_variables)]
                        let res = extrinsic.clone().dispatch(origin.clone());
                        elapsed += now.elapsed();
                        extr_ok |= res.is_ok();

                        log::debug!(target: "fuzz::result", "    result:     {}", format_dispatch_result(&res));

                        if let Err(e) = &res {
                            if let DispatchError::BadOrigin = &e.error {
                                // BadOrigin: retry with next origin
                                continue;
                            }
                        }

                        // By default only try one origin, unless the error is BadOrigin
                        break;
                    }

                    FC::after_each_extr(&extrinsic, &mut num_events_before_inner, extr_ok, is_root);
                }
                ExtrOrPseudo::Pseudo(fuzz_call) => {
                    match fuzz_call {
                        FuzzRuntimeCall::SetOrigin {
                            origin: new_origin,
                            retry_as_root,
                            try_root_first,
                        } => {
                            origin_sm.origin = new_origin;
                            origin_sm.retry_as_root = retry_as_root;
                            origin_sm.try_root_first = try_root_first;
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
                        FuzzRuntimeCall::NewBlock => {
                            // Unimplemented
                            continue;
                        }
                        FuzzRuntimeCall::NewSession => {
                            // Unimplemented
                            continue;
                        }
                    }
                }
            }
        }

        ExtStorageTracer::set_block_context(BlockContext::TryState);
        // Disabled this to improve performance
        /*
        finalize_block(elapsed);
        check_invariants(block, initial_total_issuance, block_rewards.get());
         */
        // Assert that it is not possible to mint tokens using the allowed extrinsics
        let final_total_issuance = TotalIssuance::<Runtime>::get();
        // Some extrinsics burn tokens so final issuance can be lower
        assert!(
            initial_total_issuance >= final_total_issuance,
            "{} >= {}",
            initial_total_issuance,
            final_total_issuance
        );
    });

    //ext.tracer.print_summary();
    FC::after_all(ext);
}

/// Start fuzzing a genesis raw spec generated by zombienet.
/// This runs `on_initialize` and `on_finalize` for multiple blocks.
pub fn fuzz_zombie<FC: FuzzerConfig<ExtrOrPseudo = ExtrOrPseudo>>(data: &[u8]) {
    FUZZ_MAIN_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
    //println!("data: {:?}", data);
    let mut extrinsic_data = data;
    //#[allow(deprecated)]
    let mut extrinsics: Vec<ExtrOrPseudo> =
        iter::from_fn(|| DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
            .filter(FC::extrinsics_filter)
            .collect();

    if extrinsics.iter().all(|x| match x {
        ExtrOrPseudo::Extr(_) => false,
        ExtrOrPseudo::Pseudo(_) => true,
    }) {
        // empty extrinsics or all extrinsics pseudo: do not test
        return;
    }

    //println!("{:?}", extrinsics);

    let mut block_state = BlockState::initial();

    let mut ext_parts = FC::externalities_parts();
    let mut ext = FC::ext_new(&mut ext_parts);

    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        let initial_total_issuance = TotalIssuance::<Runtime>::get();

        let first_era = ExternalValidators::current_era().unwrap();

        block_state.block = System::block_number();
        let last_timestamp = pallet_timestamp::Now::<Runtime>::get();
        // Technically this should be last_timestamp / slot_duration, but this also works
        block_state.slot = last_timestamp;

        initialize_block(&mut block_state);

        let num_events_before = System::events().len();
        let mut num_events_before_inner = System::events().len();

        // Origin is kind of like a state machine
        // By default we try using Alice, and if we get Err::BadOrigin, we check if root_can_call
        // that extrinsic, and if so retry as root
        let mut origin_sm = OriginStateMachine::new();

        //let mut seen_values = SeenValues::default();
        //test_mutate(&mut extrinsics, &mut seen_values);

        for extrinsic in extrinsics {
            if block_state.num_created_blocks >= 200 {
                // Hard limit of 200 blocks, hopefully its enough to test all the Era stuff.
                // We use fast-runtime so 1 era = 3 sessions and 1 session = 10 blocks.
                assert!(block_state.last_era - first_era > 2, "{:?}", block_state.last_era);
                break;
            }
            match extrinsic {
                ExtrOrPseudo::Extr(extrinsic) => {
                    let eww = extrinsic.get_dispatch_info();
                    if eww.call_weight.ref_time() + eww.extension_weight.ref_time()
                        >= 2 * WEIGHT_REF_TIME_PER_SECOND
                    {
                        // This extrinsic weight is greater than the allowed block weight.
                        // This is normal, it can happen for:
                        // * Disabled extrinsics. When an extrinsic benchmark fails, its weight is set
                        //   to a high value to effectively disable it.
                        // * High input params. Some extrinsics have a weight that depends on some
                        //   input. If we set that input to u32::MAX, the weight will also probably be
                        //   u32::MAX. So we ignore this call.
                        //log::warn!("Extrinsic would exhaust block weight, skipping");
                        continue;
                    }

                    let mut extr_ok = false;
                    let mut is_root = false;
                    num_events_before_inner = System::events().len();
                    for origin in origin_sm.get_origins(&extrinsic) {
                        block_state.weight.saturating_accrue(eww.call_weight);
                        block_state.weight.saturating_accrue(eww.extension_weight);
                        if block_state.weight.ref_time() >= 2 * WEIGHT_REF_TIME_PER_SECOND {
                            // The extrinsic fits in an empty block, but not in this block. So create a new block
                            // TODO: the fuzzer should be faster if we ignore block weight and create bigger blocks than expected
                            let ignore_block_weight_limit = true;
                            if !ignore_block_weight_limit {
                                finalize_block(&mut block_state);
                                initialize_block(&mut block_state);
                                block_state.weight.saturating_accrue(eww.call_weight);
                                block_state.weight.saturating_accrue(eww.extension_weight);

                                assert_eq!(
                                    block_state.weight.ref_time() >= 2 * WEIGHT_REF_TIME_PER_SECOND,
                                    false,
                                    "initialize_block should reset block weight to 0, and we checked that the extrinsic weight fits in an empty block above"
                                );
                            }
                        }

                        log::debug!(target: "fuzz::origin", "\n    origin:     {origin:?}");
                        log::debug!(target: "fuzz::call", "    call:       {extrinsic:?}");

                        if origin.caller.is_root() {
                            is_root = true;
                            ExtStorageTracer::set_block_context(BlockContext::ExtrinsicRoot);
                        } else {
                            is_root = false;
                            ExtStorageTracer::set_block_context(BlockContext::ExtrinsicSigned);
                        }

                        let now = Instant::now(); // We get the current time for timing purposes.
                        #[allow(unused_variables)]
                        let res = extrinsic.clone().dispatch(origin.clone());
                        block_state.elapsed += now.elapsed();
                        extr_ok |= res.is_ok();

                        log::debug!(target: "fuzz::result", "    result:     {}", format_dispatch_result(&res));

                        if let Err(e) = &res {
                            if let DispatchError::BadOrigin = &e.error {
                                // BadOrigin: retry with next origin
                                continue;
                            }
                        }

                        // By default only try one origin, unless the error is BadOrigin
                        break;
                    }

                    FC::after_each_extr(&extrinsic, &mut num_events_before_inner, extr_ok, is_root);
                }
                ExtrOrPseudo::Pseudo(fuzz_call) => {
                    match fuzz_call {
                        FuzzRuntimeCall::SetOrigin {
                            origin: new_origin,
                            retry_as_root,
                            try_root_first,
                        } => {
                            origin_sm.origin = new_origin;
                            origin_sm.retry_as_root = retry_as_root;
                            origin_sm.try_root_first = try_root_first;
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
                        FuzzRuntimeCall::NewBlock => {
                            finalize_block(&mut block_state);
                            initialize_block(&mut block_state);
                            continue;
                        }
                        FuzzRuntimeCall::NewSession => {
                            let session_start = Session::current_index();
                            let mut count = 0u32;
                            loop {
                                count += 1;
                                // Since sessions are timestamp based in relay chain, we can just
                                // mock the timestamp and create one block only
                                // 1 session = 10 blocks so increase timestamp by 10 slots
                                block_state.slot += 10;

                                finalize_block(&mut block_state);
                                initialize_block(&mut block_state);

                                let new_session = Session::current_index();

                                if new_session > session_start {
                                    break;
                                }
                            }
                            // This assert is to ensure that the +10 above is correct.
                            // If session length changes this will panic, so increase the +10.
                            assert_eq!(count, 1, "NewSession: created {} blocks", count);
                            continue;
                        }
                    }
                }
            }
        }

        finalize_block(&mut block_state);
        ExtStorageTracer::set_block_context(BlockContext::TryState);
        // Disabled this to improve performance
        check_invariants(
            block_state.block,
            initial_total_issuance,
            block_state.block_rewards,
        );
        // Assert that it is not possible to mint tokens using the allowed extrinsics
        let final_total_issuance = TotalIssuance::<Runtime>::get();
        // Some extrinsics burn tokens so final issuance can be lower
        assert!(
            initial_total_issuance.saturating_add(block_state.block_rewards)
                >= final_total_issuance,
            "{} >= {}",
            initial_total_issuance,
            final_total_issuance
        );
    });

    FC::after_all(ext);
}

/// Input: a chain state snapshot before on_initialize
/// Output: a hex file with the storage state after on_initialize, but before on_finalize
/// It may create up to 100 blocks to finish any pending multi block migrations.
/// That is the expected input of the `fuzz_live_oneblock` target
pub fn update_snapshot_after_on_initialize(
    input_snapshot_path: &str,
    output_hexsnapshot_path: &str,
) {
    FUZZ_MAIN_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);

    let mut block_state = BlockState::initial();

    use sp_runtime::traits::BlakeTwo256;

    use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
    let mut overlay = OverlayedChanges::default();
    let input_snapshot_bytes = std::fs::read(input_snapshot_path).unwrap();
    let (storage, root, shared_cache) = &read_snapshot::read_snapshot(&input_snapshot_bytes);
    let root = *root;
    let cache = shared_cache.local_cache();
    let mut backend: TrieBackend<_, BlakeTwo256> =
        TrieBackendBuilder::new_with_cache(storage, root, cache).build();
    let extensions = None;
    let mut ext = Ext::new(&mut overlay, &backend, extensions);
    // Here let's not mock the storage root, to have a better snapshot
    // No WithoutStorageRoot
    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        use {
            frame_support::migrations::MultiStepMigrator,
            std::{fs::File, io::Write},
        };

        block_state.block = System::block_number();
        let last_timestamp = pallet_timestamp::Now::<Runtime>::get();
        // Technically this should be last_timestamp / slot_duration, but this also works
        block_state.slot = last_timestamp;

        // If need to export storage, it means that the snapshot is not stored after on_initialize
        initialize_block(&mut block_state);

        // Create up to 100 blocks to ensure migrations have finished
        for _ in 0..100 {
            finalize_block(&mut block_state);
            initialize_block(&mut block_state);

            if MultiBlockMigrations::ongoing() == false {
                break;
            }
        }

        // Do not finalize last block, we want to store the state before on_finalize
        //finalize_block(elapsed);

        assert_eq!(
            MultiBlockMigrations::ongoing(),
            false,
            "After 100 blocks, multiblock migration still ongoing, wtf?"
        );

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

        let output_file_path = output_hexsnapshot_path; //"fuzz_starlight_live_export_state.hexsnap.txt";
        let mut output_file = File::create(output_file_path)
            .inspect_err(|e| {
                log::error!("Failed to create output file: {}", e);
            })
            .unwrap();

        for (key, value) in all_key_values {
            writeln!(
                output_file,
                "\"0x{}\": \"0x{}\",",
                hex::encode(&key),
                hex::encode(&value)
            )
            .expect("failed to writeln");
        }
        output_file.flush().unwrap();
        log::info!("Exported hex snapshot to file {}", output_file_path);
    });
}

pub fn fuzz_init<FC: FuzzerConfig>() {
    FUZZ_INIT_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);

    // Uncomment to init logger
    init_logger();

    // Initialize genesis storage
    FC::genesis_storage();
    FC::genesis_storage_simple();

    // Initialize stuff related to metadata (needs externalities)
    use sp_runtime::traits::BlakeTwo256;

    use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
    let mut overlay = OverlayedChanges::default();
    let (storage, root, shared_cache) = FC::genesis_storage();
    let root = *root;
    let cache = shared_cache.local_cache();
    let backend: TrieBackend<_, BlakeTwo256> =
        TrieBackendBuilder::new_with_cache(storage, root, cache).build();
    let extensions = None;
    let mut ext = Ext::new(&mut overlay, &backend, extensions);
    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        &*METADATA;
    });
}

fn extrinsics_iter_ignore_errors(
    mut extrinsic_data: &[u8],
) -> impl Iterator<Item = RuntimeCall> + use<'_> {
    iter::from_fn(move || {
        loop {
            match DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data) {
                Ok(x) => return Some(x),
                Err(_e) => {
                    if extrinsic_data.is_empty() {
                        return None;
                    } else {
                        extrinsic_data = &extrinsic_data[1..];
                        continue;
                    }
                }
            }
        }
    })
}

pub fn extrinsics_iter(mut extrinsic_data: &[u8]) -> impl Iterator<Item = ExtrOrPseudo> + use<'_> {
    iter::from_fn(move || DecodeLimit::decode_with_depth_limit(64, &mut extrinsic_data).ok())
}

/// Same as `extrinsics_iter` but only decodes `RuntimeCall` variant, errors on any other variant
pub fn extrinsics_iter_only_runtime_calls(
    mut extrinsic_data: &[u8],
) -> impl Iterator<Item = ExtrOrPseudo> + use<'_> {
    // Use new types to keep encoded byte compatibility with the real `ExtrOrPseudo`.
    // So any bytes that decode to a valid `ExtrOrPseudo::RuntimeCall` will be valid here, and vice-versa.
    #[derive(Debug, Encode, Decode, TypeInfo, Clone)]
    pub struct ExtrOrPseudoOnlyExtr {
        tag: u8,
        runtime_call: RuntimeCall,
    }

    iter::from_fn(move || {
        // Force tag to always be 0, emulating the 0 tag from the ExtrOrPseudo enum
        if extrinsic_data.get(0).copied() != Some(0) {
            return None;
        }
        ExtrOrPseudoOnlyExtr::decode_with_depth_limit(64, &mut extrinsic_data).ok()
    })
    .map(|x| {
        assert_eq!(x.tag, 0);
        ExtrOrPseudo::Extr(x.runtime_call)
    })
}

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

pub fn fuzz_init_only_logger() {
    init_logger();
}

pub fn fuzz_decode_calls(data: &[u8]) {
    //println!("data: {:?}", data);
    let num_extrinsics = one_extrinsic_iter(data).count();
    assert!(num_extrinsics <= 1);
}
