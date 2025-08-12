use crate::create_storage::ext_to_simple_storage;
use crate::metadata::unhash_storage_key;
pub use crate::storage_tracer::tracing_externalities::TracingExt;
use crate::storage_tracer::tracing_externalities::{ExtStorageTracer, ReadOrWrite};
use crate::{
    CallableCallFor, ExtrOrPseudo, FuzzRuntimeCall, FuzzerConfig, get_origin,
    recursively_find_call, root_can_call,
};
use dancelight_runtime::Session;
use itertools::{EitherOrBoth, Itertools};
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use many_to_many::ManyToMany;
use sp_trie::recorder::Recorder;
use std::collections::{HashMap, HashSet};
use {
    cumulus_primitives_core::ParaId,
    dancelight_runtime::{
        AccountId, AllPalletsWithSystem, Balance, Balances, CollatorsInflationRatePerBlock,
        ContainerRegistrar, Executive, ExternalValidators, Header, InflationRewards,
        MultiBlockMigrations, OriginCaller, ParaInherent, Runtime, RuntimeCall, RuntimeOrigin,
        Timestamp, UncheckedExtrinsic, ValidatorsInflationRatePerEra,
        genesis_config_presets::get_authority_keys_from_seed,
    },
    dancelight_runtime_constants::time::SLOT_DURATION,
    dp_container_chain_genesis_data::ContainerChainGenesisData,
    dp_core::well_known_keys::PARAS_HEADS_INDEX,
    frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed, v15::RuntimeMetadataV15},
    frame_support::{
        Hashable,
        dispatch::{CallableCallFor as CallableCallForG, GetDispatchInfo},
        pallet_prelude::Weight,
        storage::unhashed,
        traits::{Currency, IntegrityTest, OriginTrait, TryState, TryStateSelect},
        weights::constants::WEIGHT_REF_TIME_PER_SECOND,
    },
    frame_system::Account,
    nimbus_primitives::{NIMBUS_ENGINE_ID, NimbusId},
    pallet_balances::{Holds, TotalIssuance},
    pallet_configuration::HostConfiguration,
    parity_scale_codec::{DecodeLimit, Encode},
    polkadot_core_primitives::{BlockNumber, Signature},
    primitives::{SchedulerParams, ValidationCode},
    rand::{Rng, SeedableRng, seq::IndexedRandom},
    scale_info::{PortableRegistry, TypeInfo},
    scale_value::{Composite, ValueDef},
    sp_consensus_aura::{AURA_ENGINE_ID, Slot},
    sp_consensus_babe::{
        BABE_ENGINE_ID,
        digests::{PreDigest, SecondaryPlainPreDigest},
    },
    sp_core::{Decode, Get, H256, Pair, Public, sr25519},
    sp_inherents::InherentDataProvider,
    sp_runtime::{
        Digest, DigestItem, DispatchError, Perbill, Saturating, Storage,
        traits::{BlakeTwo256, Dispatchable, Header as HeaderT, IdentifyAccount, Verify},
    },
    sp_state_machine::{
        BasicExternalities, Ext, LayoutV1, MemoryDB, TrieBackend, TrieBackendBuilder,
    },
    sp_storage::StateVersion,
    sp_trie::{
        GenericMemoryDB,
        cache::{CacheSize, SharedTrieCache},
    },
    std::{
        any::TypeId,
        cell::Cell,
        cmp::max,
        collections::BTreeMap,
        io::Write,
        iter,
        marker::PhantomData,
        sync::{Arc, atomic::AtomicBool},
        time::{Duration, Instant},
    },
};

pub type CallIndex = (u8, u8);
pub type StorageKey = Arc<[u8]>;

#[derive(Clone, Debug)]
pub enum Value {
    Read(Vec<u8>),
    Write(Vec<u8>),
}

mod many_to_many {
    use std::borrow::Borrow;
    use std::collections::{HashMap, HashSet};
    use std::hash::Hash;
    use std::sync::Arc;

    /// Generic bidirectional many↔many relation backed by two hash maps.
    #[derive(Debug, Default, Clone)]
    pub struct ManyToMany<L, R> {
        l2r: HashMap<L, HashSet<R>>,
        r2l: HashMap<R, HashSet<L>>,
    }

    impl<L, R> ManyToMany<L, R>
    where
        L: Eq + Hash + Clone,
        R: Eq + Hash + Clone,
    {
        /// Insert an edge (l, r). Returns true if it was newly inserted.
        pub fn insert(&mut self, l: L, r: R) -> bool {
            let added_lr = self.l2r.entry(l.clone()).or_default().insert(r.clone());
            if added_lr {
                self.r2l.entry(r).or_default().insert(l);
            }
            added_lr
        }

        /// Remove a specific edge. Returns true if it existed.
        pub fn remove_edge(&mut self, l: &L, r: &R) -> bool {
            let mut removed = false;

            if let Some(rs) = self.l2r.get_mut(l) {
                if rs.remove(r) {
                    removed = true;
                }
                if rs.is_empty() {
                    self.l2r.remove(l);
                }
            }
            if removed {
                if let Some(ls) = self.r2l.get_mut(r) {
                    ls.remove(l);
                    if ls.is_empty() {
                        self.r2l.remove(r);
                    }
                }
            }
            removed
        }

        /// Remove a left node and all its edges. Returns the removed right set (if any).
        pub fn remove_left(&mut self, l: &L) -> Option<HashSet<R>> {
            let rs = self.l2r.remove(l)?;
            for r in &rs {
                if let Some(ls) = self.r2l.get_mut(r) {
                    ls.remove(l);
                    if ls.is_empty() {
                        self.r2l.remove(r);
                    }
                }
            }
            Some(rs)
        }

        /// Remove a right node and all its edges. Returns the removed left set (if any).
        pub fn remove_right(&mut self, r: &R) -> Option<HashSet<L>> {
            let ls = self.r2l.remove(r)?;
            for l in &ls {
                if let Some(rs) = self.l2r.get_mut(l) {
                    rs.remove(r);
                    if rs.is_empty() {
                        self.l2r.remove(l);
                    }
                }
            }
            Some(ls)
        }

        /// Replace all edges from `l` with `new_rs`.
        pub fn replace_left<I>(&mut self, l: L, new_rs: I)
        where
            I: IntoIterator<Item = R>,
        {
            // remove old
            self.remove_left(&l);
            // add new
            for r in new_rs {
                self.insert(l.clone(), r);
            }
        }

        /// Replace all edges from `r` with `new_ls`.
        pub fn replace_right<I>(&mut self, r: R, new_ls: I)
        where
            I: IntoIterator<Item = L>,
        {
            self.remove_right(&r);
            for l in new_ls {
                self.insert(l, r.clone());
            }
        }

        pub fn contains_edge(&self, l: &L, r: &R) -> bool {
            self.l2r.get(l).map_or(false, |rs| rs.contains(r))
        }

        pub fn left_len(&self) -> usize {
            self.l2r.len()
        }
        pub fn right_len(&self) -> usize {
            self.r2l.len()
        }

        /// Borrowing lookups (works when L/R implement Borrow<Q>, e.g. Arc<[u8]> ~ &[u8])
        pub fn left_values<'a, 'b>(&'a self, l: &L) -> impl Iterator<Item = &'a R> + 'a {
            self.l2r.get(l).into_iter().flat_map(|s| s.iter())
        }
        pub fn right_values<'a, 'b>(&'a self, r: &R) -> impl Iterator<Item = &'a L> + 'a {
            self.r2l.get(r).into_iter().flat_map(|s| s.iter())
        }

        pub fn left_values_by<'a, Q>(&'a self, l: &Q) -> impl Iterator<Item = &'a R> + 'a
        where
            L: Borrow<Q>,
            Q: Eq + Hash + ?Sized,
        {
            self.l2r.get(l).into_iter().flat_map(|s| s.iter())
        }

        pub fn right_values_by<'a, Q>(&'a self, r: &Q) -> impl Iterator<Item = &'a L> + 'a
        where
            R: Borrow<Q>,
            Q: Eq + Hash + ?Sized,
        {
            self.r2l.get(r).into_iter().flat_map(|s| s.iter())
        }

        /// Owned helpers if you want `Vec`s.
        pub fn left_values_vec(&self, l: &L) -> Vec<R> {
            self.left_values(l).cloned().collect()
        }
        pub fn right_values_vec(&self, r: &R) -> Vec<L> {
            self.right_values(r).cloned().collect()
        }
    }
}

mod tracing_externalities {
    use sp_externalities::{Error, Extension, ExtensionStore, Externalities, MultiRemovalResults};
    use sp_storage::{ChildInfo, StateVersion, TrackedStorageKey};
    use std::any::{Any, TypeId};
    use std::backtrace::Backtrace;
    use std::collections::HashSet;

    #[derive(Debug)]
    pub enum ReadOrWrite {
        Read(Vec<u8>),
        Write(Vec<u8>, Vec<u8>),
        Remove(Vec<u8>),
        Append(Vec<u8>, Vec<u8>),
        KillPrefix(Vec<u8>),
        KillPrefixPartial(Vec<u8>, Vec<u8>),
        StartTransaction,
        RollbackTransaction,
        CommitTransaction,
    }

    #[derive(Debug)]
    pub struct ExtStorageTracer {
        pub trace: Vec<ReadOrWrite>,
        pub whitelisted: HashSet<Vec<u8>>,
    }

    impl Default for ExtStorageTracer {
        fn default() -> Self {
            /*
            let whitelisted = HashSet::from_iter([
                b":transaction_level:".to_vec(),
                // MaintenanceMode MaintenanceMode
                // Checked for each extrinsic dispatch to decide whether to allow it or not
                hex::decode("e11a6a33190df528cea25070debd8681e11a6a33190df528cea25070debd8681")
                    .unwrap(),
                // System Number
                hex::decode("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac")
                    .unwrap(),
                // System EventCount
                hex::decode("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850")
                    .unwrap(),
                // System Events
                hex::decode("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7")
                    .unwrap(),
                // System ExecutionPhase
                hex::decode("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a")
                    .unwrap(),
                // custom prefix for relay_dispatch_queue_size
                // annoying because it cannot be decoded from metadata, so ignore it
                // it is a storage map so the last bytes can be different, but this one is the most common
                hex::decode("f5207f03cfdce586301014700e2c2593fad157e461d71fd4c1f936839a5f1f3eb4def25cfda6ef3a00000000").unwrap(),
            ]);
             */
            // Do not use whitelist
            let whitelisted = Default::default();

            Self {
                trace: Default::default(),
                whitelisted,
            }
        }
    }

    impl ExtStorageTracer {
        fn mark_read<K: Into<Vec<u8>> + AsRef<[u8]> + std::hash::Hash + Eq>(&mut self, key: K) {
            if self.whitelisted.contains(key.as_ref()) {
                return;
            }

            /*
            // Backtrace works, and shows line numbers if compiled with debug = 1
            let backtrace = Backtrace::force_capture();
            println!("mark_read: {}", backtrace);
            */

            self.trace.push(ReadOrWrite::Read(key.into()));
        }
        fn mark_write<K: Into<Vec<u8>> + AsRef<[u8]> + std::hash::Hash + Eq, V: Into<Vec<u8>>>(
            &mut self,
            key: K,
            val: Option<V>,
        ) {
            if self.whitelisted.contains(key.as_ref()) {
                return;
            }

            /*
            #[deprecated = "Use `relay_dispatch_queue_remaining_capacity` instead"]
            pub fn relay_dispatch_queue_size(para_id: Id) -> Vec<u8> {
                let prefix = hex!["f5207f03cfdce586301014700e2c2593fad157e461d71fd4c1f936839a5f1f3e"];
             */
            /*
            if hex::encode(key.as_ref()).starts_with("f5207f03cfdce586301014700e2c2593fad") {
                //panic!("look at backtrace")
                let backtrace = Backtrace::force_capture();
                println!("write to f5207f03cfdce586301014700e2c2593fad: {}", backtrace);
            }
             */

            match val {
                Some(val) => self.trace.push(ReadOrWrite::Write(key.into(), val.into())),
                None => self.trace.push(ReadOrWrite::Remove(key.into())),
            }
        }
        fn mark_append<K: Into<Vec<u8>> + AsRef<[u8]> + std::hash::Hash + Eq, V: Into<Vec<u8>>>(
            &mut self,
            key: K,
            val: V,
        ) {
            if self.whitelisted.contains(key.as_ref()) {
                return;
            }
            self.trace.push(ReadOrWrite::Append(key.into(), val.into()));
        }
        fn mark_kill_prefix<
            K: Into<Vec<u8>> + AsRef<[u8]> + std::hash::Hash + Eq,
            V: Into<Vec<u8>>,
        >(
            &mut self,
            key: K,
            cursor: Option<V>,
        ) {
            if self.whitelisted.contains(key.as_ref()) {
                return;
            }
            match cursor {
                Some(cursor) => self
                    .trace
                    .push(ReadOrWrite::KillPrefixPartial(key.into(), cursor.into())),
                None => self.trace.push(ReadOrWrite::KillPrefix(key.into())),
            }
        }
        fn storage_start_transaction(&mut self) {
            self.trace.push(ReadOrWrite::StartTransaction);
        }
        fn storage_rollback_transaction(&mut self) {
            self.trace.push(ReadOrWrite::RollbackTransaction);
        }
        fn storage_commit_transaction(&mut self) {
            self.trace.push(ReadOrWrite::CommitTransaction);
        }
        pub fn print_summary(&self) {
            for x in &self.trace {
                match x {
                    ReadOrWrite::Read(k) => {
                        let key_hex = hex::encode(k);
                        println!("READ   {}", key_hex);
                    }
                    ReadOrWrite::Write(k, v) => {
                        let key_hex = hex::encode(k);
                        let val_hex = hex::encode(v);
                        println!("WRITE  {} : {}", key_hex, val_hex);
                    }
                    ReadOrWrite::Remove(k) => {
                        let key_hex = hex::encode(k);
                        println!("DELETE {}", key_hex);
                    }
                    ReadOrWrite::Append(k, v) => {
                        let key_hex = hex::encode(k);
                        let val_hex = hex::encode(v);
                        println!("APPEND {} : {}", key_hex, val_hex);
                    }
                    ReadOrWrite::KillPrefix(k) => {
                        let key_hex = hex::encode(k);
                        println!("KILL*  {}*", key_hex);
                    }
                    ReadOrWrite::KillPrefixPartial(k, cursor) => {
                        let key_hex = hex::encode(k);
                        let cursor_hex = hex::encode(cursor);
                        println!("KILLPA {} .. {}", key_hex, cursor_hex);
                    }
                    ReadOrWrite::StartTransaction => {
                        println!("START TRANSACTION");
                    }
                    ReadOrWrite::RollbackTransaction => {
                        println!("ROLLBACK TRANSACTION");
                    }
                    ReadOrWrite::CommitTransaction => {
                        println!("COMMIT TRANSACTION");
                    }
                }
            }
        }
    }

    pub struct TracingExt<T> {
        inner: T,
        pub tracer: ExtStorageTracer,
    }

    impl<T> TracingExt<T> {
        pub fn new(inner: T) -> Self {
            Self {
                inner,
                tracer: Default::default(),
            }
        }
    }

    impl<T: ExtensionStore> ExtensionStore for TracingExt<T> {
        fn extension_by_type_id(&mut self, type_id: TypeId) -> Option<&mut dyn Any> {
            self.inner.extension_by_type_id(type_id)
        }

        fn register_extension_with_type_id(
            &mut self,
            type_id: TypeId,
            extension: Box<dyn Extension>,
        ) -> Result<(), Error> {
            self.inner
                .register_extension_with_type_id(type_id, extension)
        }

        fn deregister_extension_by_type_id(&mut self, type_id: TypeId) -> Result<(), Error> {
            self.inner.deregister_extension_by_type_id(type_id)
        }
    }

    impl<T: Externalities> Externalities for TracingExt<T> {
        fn set_offchain_storage(&mut self, key: &[u8], value: Option<&[u8]>) {
            self.inner.set_offchain_storage(key, value)
        }

        fn storage(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            self.tracer.mark_read(key);
            self.inner.storage(key)
        }

        fn storage_hash(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            todo!()
        }

        fn child_storage_hash(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>> {
            todo!()
        }

        fn child_storage(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>> {
            todo!()
        }

        fn next_storage_key(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            let res = self.inner.next_storage_key(key);

            // This function returns the next storage key after "key"
            // So it does not read the input `key`, but actually it reads the next, `res` key
            // I guess? Not sure. Maybe it doesn't matter.
            if let Some(res) = &res {
                self.tracer.mark_read(res.as_slice());
            }

            res
        }

        fn next_child_storage_key(
            &mut self,
            child_info: &ChildInfo,
            key: &[u8],
        ) -> Option<Vec<u8>> {
            todo!()
        }

        fn kill_child_storage(
            &mut self,
            child_info: &ChildInfo,
            maybe_limit: Option<u32>,
            maybe_cursor: Option<&[u8]>,
        ) -> MultiRemovalResults {
            todo!()
        }

        fn clear_prefix(
            &mut self,
            prefix: &[u8],
            maybe_limit: Option<u32>,
            maybe_cursor: Option<&[u8]>,
        ) -> MultiRemovalResults {
            let res = self.inner.clear_prefix(prefix, maybe_limit, maybe_cursor);

            let cursor = match &res.maybe_cursor {
                Some(cursor) => Some(cursor.as_slice()),
                None => None,
            };
            self.tracer.mark_kill_prefix(prefix, cursor);

            res
        }

        fn clear_child_prefix(
            &mut self,
            child_info: &ChildInfo,
            prefix: &[u8],
            maybe_limit: Option<u32>,
            maybe_cursor: Option<&[u8]>,
        ) -> MultiRemovalResults {
            todo!()
        }

        fn place_storage(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
            // TODO: writes need to detect if we are inside a transaction, as those writes will rollback so they are not real writes...
            let vref = match &value {
                Some(x) => Some(x.as_slice()),
                None => None,
            };
            self.tracer.mark_write(key.as_slice(), vref);
            self.inner.place_storage(key, value)
        }

        fn place_child_storage(
            &mut self,
            child_info: &ChildInfo,
            key: Vec<u8>,
            value: Option<Vec<u8>>,
        ) {
            todo!()
        }

        fn storage_root(&mut self, state_version: StateVersion) -> Vec<u8> {
            self.inner.storage_root(state_version)
        }

        fn child_storage_root(
            &mut self,
            child_info: &ChildInfo,
            state_version: StateVersion,
        ) -> Vec<u8> {
            todo!()
        }

        fn storage_append(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.tracer.mark_append(key.as_slice(), value.as_slice());
            self.inner.storage_append(key, value)
        }

        fn storage_start_transaction(&mut self) {
            self.tracer.storage_start_transaction();
            self.inner.storage_start_transaction()
        }

        fn storage_rollback_transaction(&mut self) -> Result<(), ()> {
            self.tracer.storage_rollback_transaction();
            self.inner.storage_rollback_transaction()
        }

        fn storage_commit_transaction(&mut self) -> Result<(), ()> {
            self.tracer.storage_commit_transaction();
            self.inner.storage_commit_transaction()
        }

        fn wipe(&mut self) {
            todo!()
        }

        fn commit(&mut self) {
            todo!()
        }

        fn read_write_count(&self) -> (u32, u32, u32, u32) {
            todo!()
        }

        fn reset_read_write_count(&mut self) {
            todo!()
        }

        fn get_whitelist(&self) -> Vec<TrackedStorageKey> {
            todo!()
        }

        fn set_whitelist(&mut self, new: Vec<TrackedStorageKey>) {
            todo!()
        }

        fn get_read_and_written_keys(&self) -> Vec<(Vec<u8>, u32, u32, bool)> {
            todo!()
        }
    }
}

#[derive(Default, Debug)]
pub struct StorageTracer {
    readers: ManyToMany<CallIndex, StorageKey>,
    writers: ManyToMany<CallIndex, StorageKey>,
    // histogram of key => num_reads
    top_reads: HashMap<Vec<u8>, u32>,
    // histogram of key => num_writes
    top_writes: HashMap<Vec<u8>, u32>,
}

impl StorageTracer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Union semantics: adds edges for this call (duplicates ignored).
    pub fn insert<I>(&mut self, call: CallIndex, values: I)
    where
        I: IntoIterator<Item = Value>,
    {
        for v in values {
            match v {
                Value::Read(k) => {
                    self.readers.insert(call, Arc::<[u8]>::from(k));
                }
                Value::Write(k) => {
                    self.writers.insert(call, Arc::<[u8]>::from(k));
                }
            }
        }
    }

    /// Replace semantics: removes previous edges for `call` then adds these.
    pub fn replace<I>(&mut self, call: CallIndex, values: I)
    where
        I: IntoIterator<Item = Value>,
    {
        self.readers.remove_left(&call);
        self.writers.remove_left(&call);
        self.insert(call, values);
    }

    // ---- Queries by CallIndex ----
    pub fn get_read<'a>(&'a self, call: &CallIndex) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.readers.left_values(call).map(|k| k.as_ref())
    }
    pub fn get_write<'a>(&'a self, call: &CallIndex) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.writers.left_values(call).map(|k| k.as_ref())
    }

    // ---- Reverse queries by key (borrowed &[u8] works with Arc<[u8]>) ----
    pub fn get_readers<'a>(&'a self, key: &'a [u8]) -> impl Iterator<Item = &'a CallIndex> + 'a {
        self.readers.right_values_by(key)
    }
    pub fn get_writers<'a>(&'a self, key: &'a [u8]) -> impl Iterator<Item = &'a CallIndex> + 'a {
        self.writers.right_values_by(key)
    }

    // Owned conveniences
    pub fn get_read_vec(&self, call: &CallIndex) -> Vec<Vec<u8>> {
        self.get_read(call).map(|s| s.to_vec()).collect()
    }
    pub fn get_write_vec(&self, call: &CallIndex) -> Vec<Vec<u8>> {
        self.get_write(call).map(|s| s.to_vec()).collect()
    }
    pub fn get_readers_vec(&self, key: &[u8]) -> Vec<CallIndex> {
        self.get_readers(key).copied().collect()
    }
    pub fn get_writers_vec(&self, key: &[u8]) -> Vec<CallIndex> {
        self.get_writers(key).copied().collect()
    }

    pub fn update_histograms(&mut self, ext_tracer: &ExtStorageTracer) {
        for x in ext_tracer.trace.iter() {
            match x {
                ReadOrWrite::Read(key) => {
                    *self.top_reads.entry(key.clone()).or_insert(0) += 1;
                }
                ReadOrWrite::Write(key, _) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                }
                ReadOrWrite::Remove(key) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                }
                ReadOrWrite::Append(key, _) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                }
                ReadOrWrite::KillPrefix(key) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                }
                ReadOrWrite::KillPrefixPartial(key, _) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                }
                ReadOrWrite::StartTransaction => {}
                ReadOrWrite::RollbackTransaction => {}
                ReadOrWrite::CommitTransaction => {}
            }
        }
    }

    pub fn print_histograms(&self) {
        fn print_top(map: &HashMap<Vec<u8>, u32>, heading: &str) {
            let mut items: Vec<(&[u8], u32)> =
                map.iter().map(|(k, &v)| (k.as_slice(), v)).collect();

            if items.is_empty() {
                println!("<empty>");
                return;
            }
            let k = 10.min(items.len());

            // Partition so the largest k elements (by count, then key) are in the last k slots.
            let nth_index = items.len() - k;
            items.select_nth_unstable_by(nth_index, |a, b| {
                // Ascending for the partition step (so biggest end up to the right)
                a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))
            });
            // Sort only the top-k slice for deterministic, pretty output (count desc, key asc).
            let topk = &mut items[nth_index..];
            topk.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            println!("{heading}");
            for (key, count) in topk.iter() {
                println!("{:>8}  {}", count, unhash_storage_key(key));
                println!("          {}", hex::encode(key));
            }
        }

        print_top(&self.top_reads, "Top 10 reads");
        println!();
        print_top(&self.top_writes, "Top 10 writes");
    }

    pub fn print_all_keys_alphabetical(&self) {
        let mut h = HashMap::new();

        h.extend(self.top_reads.keys().map(|k| (k, "R ")));
        for k in self.top_writes.keys() {
            let old = h.insert(k, " W");
            if old.is_some() {
                h.insert(k, "RW");
            }
        }

        let mut v: Vec<((String, String), &'static str)> = h
            .into_iter()
            .map(|(k, v)| {
                let mut pretty_key = unhash_storage_key(k);
                fn trim_32(k: &[u8]) -> &[u8] {
                    if k.len() > 32 { &k[..32] } else { k }
                }
                ((pretty_key, format!("0x{}", hex::encode(trim_32(k)))), v)
            })
            .collect();

        v.sort();

        fn merge_vals<'a>(a: &'a str, b: &'a str) -> &'a str {
            // Possible values: "R ", " W", "RW"
            // If the values are equal return one of them, done.
            // If the values are different, then at least one of them is R and at least one of them
            // is W, so the merged is RW
            if a == b { a } else { "RW" }
        }

        v.dedup_by(|a, b| {
            if a.0 == b.0 {
                a.1 = merge_vals(a.1, b.1); // mutate the first value
                true // drop `b`
            } else {
                false
            }
        });

        for ((k1, k2), v) in v {
            println!("{} {:48} {}", v, k1, k2);
        }
    }
}

/// Start fuzzing a snapshot of a live network.
/// This doesn't run `on_initialize` and `on_finalize`, everything is executed inside the same block.
/// Inherents are also not tested, the snapshot is created after the inherents.
pub fn trace_storage<FC: FuzzerConfig>(data: &[u8], storage_tracer: &mut StorageTracer) {
    //println!("data: {:?}", data);
    let mut extrinsic_data = data;
    //#[allow(deprecated)]
    let mut extrinsics: Vec<ExtrOrPseudo> =
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
                    RuntimeCall::Referenda(CallableCallFor::<dancelight_runtime::Referenda>::submit {
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

    //println!("{:?}", extrinsics);

    let mut block: u32 = 1;
    let mut weight: Weight = Weight::zero();
    let mut elapsed: Duration = Duration::ZERO;
    let mut block_rewards: Cell<u128> = Cell::new(0);
    let mut last_era: Cell<u32> = Cell::new(0);

    let initialize_block = |block: u32| {
        log::debug!(target: "fuzz::initialize", "\ninitializing block {block}");

        let validators = dancelight_runtime::Session::validators();
        let slot = Slot::from(u64::from(block + 350000000));
        let authority_index =
            u32::try_from(u64::from(slot) % u64::try_from(validators.len()).unwrap()).unwrap();
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
                let new_supply_validators =
                    ValidatorsInflationRatePerEra::get() * Balances::total_issuance();
                block_rewards.set(block_rewards.get() + new_supply_validators);
            }
        }

        Executive::initialize_block(&parent_header);

        Timestamp::set(
            RuntimeOrigin::none(),
            u64::from(block) * SLOT_DURATION + 2_100_000_000_000,
        )
        .unwrap();

        Executive::apply_extrinsic(UncheckedExtrinsic::new_unsigned(RuntimeCall::AuthorNoting(
            CallableCallFor::<dancelight_runtime::AuthorNoting>::set_latest_author_data {
                data: (),
            },
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
    use sp_state_machine::{Ext, OverlayedChanges, TrieBackendBuilder};
    let mut overlay = OverlayedChanges::default();
    let (storage, root, shared_cache) = FC::genesis_storage();
    let root = *root;
    let cache = shared_cache.local_cache();
    let mut backend: TrieBackend<_, BlakeTwo256> =
        TrieBackendBuilder::new_with_cache(storage, root, cache).build();
    let extensions = None;
    let mut ext = Ext::new(&mut overlay, &backend, extensions);
    let mut ext = TracingExt::new(ext);

    sp_externalities::set_and_run_with_externalities(&mut ext, || {
        let initial_total_issuance = TotalIssuance::<Runtime>::get();

        // The snapshot is saved after the initial on_initialize
        //initialize_block(block);

        // Origin is kind of like a state machine
        // By default we try using Alice, and if we get Err::BadOrigin, we check if root_can_call
        // that extrinsic, and if so retry as root
        let mut origin = 0;
        let mut origin_retry_as_root = true;
        let mut origin_try_root_first = false;

        //let mut seen_values = SeenValues::default();
        //test_mutate(&mut extrinsics, &mut seen_values);

        for extrinsic in extrinsics {
            // Only create 1 block, do not even finalize it
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
                    let eww = extrinsic.get_dispatch_info();
                    if eww.call_weight.ref_time() + eww.extension_weight.ref_time()
                        >= 2 * WEIGHT_REF_TIME_PER_SECOND
                    /*&&
                    match &extrinsic {
                        // Whitelist some extrinsics with big weights
                        RuntimeCall::Configuration(runtime_parachains::configuration::Call::set_hrmp_open_request_ttl { .. }) => false,
                        RuntimeCall::Hrmp(CallableCallFor::<dancelight_runtime::Hrmp>::force_process_hrmp_close { .. }) => false,
                        // I guess everything under HRMP is disabled
                        RuntimeCall::Hrmp(..) => false,
                        _ => true,
                    }*/
                    {
                        //log::error!(target: "fuzz::call", "    call:       {extrinsic:?}");
                        //panic!("Extrinsic would exhaust block weight");
                        continue;
                    }

                    let mut origin_is_root = false;
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

                    //frame_support::storage::with_transaction();

                    let now = Instant::now(); // We get the current time for timing purposes.
                    #[allow(unused_variables)]
                    let mut res = extrinsic.clone().dispatch(origin.clone());
                    elapsed += now.elapsed();

                    if origin_retry_as_root {
                        if let Err(e) = &res {
                            if let DispatchError::BadOrigin = &e.error {
                                // Retry using a different origin
                                let origin = if origin_is_root {
                                    // First we tried as root, now retry as signed origin
                                    Some(RuntimeOrigin::signed(
                                        get_origin(origin_u8.into()).clone(),
                                    ))
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
                            origin: new_origin,
                            retry_as_root,
                            try_root_first,
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
    storage_tracer.update_histograms(&ext.tracer);
}
