use crate::metadata::unhash_storage_key;
use crate::storage_tracer::tracing_externalities::ReadOrWrite;
pub use crate::storage_tracer::tracing_externalities::TracingExt;
use many_to_many::ManyToMany;
use std::collections::HashMap;
use std::{cmp::max, sync::Arc};

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

pub use tracing_externalities::BlockContext;
pub use tracing_externalities::ExtStorageTracer;
mod tracing_externalities {
    use sp_externalities::{Error, Extension, ExtensionStore, Externalities, MultiRemovalResults};
    use sp_storage::{ChildInfo, StateVersion, TrackedStorageKey};
    use std::any::{Any, TypeId};
    use std::backtrace::Backtrace;
    use std::collections::HashSet;

    #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
    pub enum BlockContext {
        OnInitialize,
        Inherents,
        ExtrinsicSigned,
        ExtrinsicRoot,
        OnFinalize,
    }

    impl BlockContext {
        pub fn from_u8(x: u8) -> Self {
            match x {
                0 => BlockContext::OnInitialize,
                1 => BlockContext::Inherents,
                2 => BlockContext::ExtrinsicSigned,
                3 => BlockContext::ExtrinsicRoot,
                4 => BlockContext::OnFinalize,
                _ => panic!("invalid value for BlockContext: {}", x),
            }
        }
        pub fn to_u8(self) -> u8 {
            match self {
                BlockContext::OnInitialize => 0,
                BlockContext::Inherents => 1,
                BlockContext::ExtrinsicSigned => 2,
                BlockContext::ExtrinsicRoot => 3,
                BlockContext::OnFinalize => 4,
            }
        }
    }

    #[derive(Debug)]
    pub enum ReadOrWrite {
        Read(Vec<u8>, usize),
        Write(Vec<u8>, Vec<u8>),
        Remove(Vec<u8>),
        Append(Vec<u8>, Vec<u8>),
        KillPrefix(Vec<u8>),
        KillPrefixPartial(Vec<u8>, Vec<u8>),
        StartTransaction,
        RollbackTransaction,
        CommitTransaction,
        ChangeContext(BlockContext),
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
        pub fn set_block_context(block_context: BlockContext) {
            frame_support::storage::unhashed::put_raw(
                b"__FUZZ_TRACER_BLOCK_CONTEXT",
                &[block_context.to_u8()],
            );
        }
        fn mark_read<K: Into<Vec<u8>> + AsRef<[u8]> + std::hash::Hash + Eq>(
            &mut self,
            key: K,
            size: usize,
        ) {
            if self.whitelisted.contains(key.as_ref()) {
                return;
            }

            /*
            // Backtrace works, and shows line numbers if compiled with debug = 1
            let backtrace = Backtrace::force_capture();
            println!("mark_read: {}", backtrace);
            */

            self.trace.push(ReadOrWrite::Read(key.into(), size));
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
        fn change_block_context(&mut self, ctx: BlockContext) {
            self.trace.push(ReadOrWrite::ChangeContext(ctx));
        }
        pub fn print_summary(&self) {
            for x in &self.trace {
                match x {
                    ReadOrWrite::Read(k, size) => {
                        let key_hex = hex::encode(k);
                        println!("READ   {} : {} bytes", key_hex, size);
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
                    ReadOrWrite::ChangeContext(_) => {
                        // We could print some headers, but not needed for now
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

        pub fn into_inner(self) -> T {
            self.inner
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
            let res = self.inner.storage(key);

            // Track read size. For keys that dont exist, put 0 bytes.
            self.tracer
                .mark_read(key, res.as_ref().map(|x| x.len()).unwrap_or(0));

            res
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
                self.tracer.mark_read(res.as_slice(), 0);
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
            if key.as_slice() == b"__FUZZ_TRACER_BLOCK_CONTEXT" {
                let x = value.unwrap()[0];
                self.tracer.change_block_context(BlockContext::from_u8(x));
                return;
            }
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
    // histogram of key => num_reads
    top_reads_by_ctx: HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
    // histogram of key => num_writes
    top_writes_by_ctx: HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
    // histogram of key => size_of_biggest_write
    biggest_reads: HashMap<Vec<u8>, u32>,
    // histogram of key => size_of_biggest_write
    biggest_writes: HashMap<Vec<u8>, u32>,
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
        let mut current_context = BlockContext::OnInitialize;
        for x in ext_tracer.trace.iter() {
            match x {
                ReadOrWrite::Read(key, size) => {
                    *self.top_reads.entry(key.clone()).or_insert(0) += 1;
                    *self
                        .top_reads_by_ctx
                        .entry(current_context)
                        .or_default()
                        .entry(key.clone())
                        .or_insert(0) += 1;
                    let bw = self.biggest_reads.entry(key.clone()).or_insert(0);
                    *bw = max(*bw, *size as u32);
                }
                ReadOrWrite::Write(key, value) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                    *self
                        .top_writes_by_ctx
                        .entry(current_context)
                        .or_default()
                        .entry(key.clone())
                        .or_insert(0) += 1;
                    let bw = self.biggest_writes.entry(key.clone()).or_insert(0);
                    *bw = max(*bw, value.len() as u32);
                }
                ReadOrWrite::Remove(key) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                    *self
                        .top_writes_by_ctx
                        .entry(current_context)
                        .or_default()
                        .entry(key.clone())
                        .or_insert(0) += 1;
                    let bw = self.biggest_writes.entry(key.clone()).or_insert(0);
                    *bw = max(*bw, 0);
                }
                ReadOrWrite::Append(key, value) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                    *self
                        .top_writes_by_ctx
                        .entry(current_context)
                        .or_default()
                        .entry(key.clone())
                        .or_insert(0) += 1;
                    let bw = self.biggest_writes.entry(key.clone()).or_insert(0);
                    // TODO: append could maybe be size = size + new, but not sure
                    *bw = max(*bw, value.len() as u32);
                }
                ReadOrWrite::KillPrefix(key) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                    *self
                        .top_writes_by_ctx
                        .entry(current_context)
                        .or_default()
                        .entry(key.clone())
                        .or_insert(0) += 1;
                    let bw = self.biggest_writes.entry(key.clone()).or_insert(0);
                    *bw = max(*bw, 0);
                }
                ReadOrWrite::KillPrefixPartial(key, _) => {
                    *self.top_writes.entry(key.clone()).or_insert(0) += 1;
                    *self
                        .top_writes_by_ctx
                        .entry(current_context)
                        .or_default()
                        .entry(key.clone())
                        .or_insert(0) += 1;
                    let bw = self.biggest_writes.entry(key.clone()).or_insert(0);
                    *bw = max(*bw, 0);
                }
                ReadOrWrite::StartTransaction => {}
                ReadOrWrite::RollbackTransaction => {}
                ReadOrWrite::CommitTransaction => {}
                ReadOrWrite::ChangeContext(ctx) => {
                    current_context = ctx.clone();
                }
            }
        }
    }

    pub fn print_histograms(&self) {
        fn print_top(map: &HashMap<Vec<u8>, u32>, heading: &str, top_k: usize) {
            let mut items: Vec<(&[u8], u32)> =
                map.iter().map(|(k, &v)| (k.as_slice(), v)).collect();

            if items.is_empty() {
                println!("<empty>");
                return;
            }
            let k = top_k.min(items.len());

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

        print_top(&self.top_reads, "Top most frequent reads", 6);
        println!();
        print_top(&self.top_writes, "Top most frequent writes", 6);
        println!();
        print_top(&self.biggest_reads, "Top biggest storage reads in bytes", 3);
        print_top(
            &self.biggest_writes,
            "Top biggest storage writes in bytes",
            3,
        );
    }

    /// Like `print_histograms`, but shows per-context RW flags for each key
    /// in a fixed order: [OnInitialize, Inherents, ExtrinsicSigned, ExtrinsicRoot, OnFinalize].
    pub fn print_histograms_by_context(&self) {
        use BlockContext::{ExtrinsicRoot, ExtrinsicSigned, Inherents, OnFinalize, OnInitialize};

        const ORDER: [BlockContext; 5] = [
            OnInitialize,
            Inherents,
            ExtrinsicSigned,
            ExtrinsicRoot,
            OnFinalize,
        ];

        fn tokens_line(
            key: &[u8],
            order: &[BlockContext; 5],
            rb: &HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
            wb: &HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
        ) -> String {
            order
                .iter()
                .map(|ctx| {
                    let r = rb.get(ctx).and_then(|m| m.get(key)).copied().unwrap_or(0);
                    let w = wb.get(ctx).and_then(|m| m.get(key)).copied().unwrap_or(0);
                    let rch = if r > 0 { 'R' } else { '-' };
                    let wch = if w > 0 { 'W' } else { '-' };
                    format!("{}{}", rch, wch)
                })
                .collect::<Vec<_>>()
                .join(" ")
        }

        fn print_top_with_context(
            flat: &HashMap<Vec<u8>, u32>,
            order: &[BlockContext; 5],
            rb: &HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
            wb: &HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
            heading: &str,
            top_k: usize,
        ) {
            let mut items: Vec<(&[u8], u32)> =
                flat.iter().map(|(k, &v)| (k.as_slice(), v)).collect();

            if items.is_empty() {
                println!("<empty>");
                return;
            }

            let k = top_k.min(items.len());
            let nth_index = items.len() - k;
            items.select_nth_unstable_by(nth_index, |a, b| {
                a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))
            });
            let topk = &mut items[nth_index..];
            topk.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            println!("{heading}");
            println!("Legend per context [Init Inh Sig Root Fin]: R=read, W=write, -=none");
            for (key, count) in topk.iter() {
                let tokens = tokens_line(key, order, rb, wb);
                // 14 = 5 tokens * 2 chars + 4 spaces between them
                println!("{:<14} {:>8}  {}", tokens, count, unhash_storage_key(key));
                println!("{:>14}      {}", "", hex::encode(key));
            }
        }

        print_top_with_context(
            &self.top_reads,
            &ORDER,
            &self.top_reads_by_ctx,
            &self.top_writes_by_ctx,
            "Top most frequent reads (with per-context RW presence)",
            6,
        );
        println!();
        print_top_with_context(
            &self.top_writes,
            &ORDER,
            &self.top_reads_by_ctx,
            &self.top_writes_by_ctx,
            "Top most frequent writes (with per-context RW presence)",
            6,
        );
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

    /// Alphabetical listing of all keys with per-context RW flags.
    /// Context order: [OnInitialize, Inherents, ExtrinsicSigned, ExtrinsicRoot, OnFinalize].
    pub fn print_all_keys_alphabetical_by_context(&self) {
        use BlockContext::{ExtrinsicRoot, ExtrinsicSigned, Inherents, OnFinalize, OnInitialize};
        const ORDER: [BlockContext; 5] = [
            OnInitialize,
            Inherents,
            ExtrinsicSigned,
            ExtrinsicRoot,
            OnFinalize,
        ];

        fn trim_32(k: &[u8]) -> &[u8] {
            if k.len() > 32 { &k[..32] } else { k }
        }

        fn tokens_for_key(
            key: &[u8],
            order: &[BlockContext; 5],
            rb: &HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
            wb: &HashMap<BlockContext, HashMap<Vec<u8>, u32>>,
        ) -> String {
            order
                .iter()
                .map(|ctx| {
                    let r = rb.get(ctx).and_then(|m| m.get(key)).copied().unwrap_or(0);
                    let w = wb.get(ctx).and_then(|m| m.get(key)).copied().unwrap_or(0);
                    let rch = if r > 0 { 'R' } else { '-' };
                    let wch = if w > 0 { 'W' } else { '-' };
                    format!("{}{}", rch, wch)
                })
                .collect::<Vec<_>>()
                .join(" ")
        }

        fn merge_tokens(a: &str, b: &str) -> String {
            // Merge "TT TT TT TT TT" element-wise (R/W union, '-' otherwise).
            let mut out = String::new();
            let mut ta = a.split_whitespace();
            let mut tb = b.split_whitespace();
            for i in 0..5 {
                let aa = ta.next().unwrap_or("--").as_bytes();
                let bb = tb.next().unwrap_or("--").as_bytes();
                let r = (aa.get(0) == Some(&b'R')) || (bb.get(0) == Some(&b'R'));
                let w = (aa.get(1) == Some(&b'W')) || (bb.get(1) == Some(&b'W'));
                if i > 0 {
                    out.push(' ');
                }
                out.push(if r { 'R' } else { '-' });
                out.push(if w { 'W' } else { '-' });
            }
            out
        }

        // Build entries from the union of keys seen anywhere.
        let mut v: Vec<((String, String), String)> = Vec::new();
        let mut push_key = |k: &Vec<u8>| {
            let tokens = tokens_for_key(k, &ORDER, &self.top_reads_by_ctx, &self.top_writes_by_ctx);
            let pretty = unhash_storage_key(k);
            let hex32 = format!("0x{}", hex::encode(trim_32(k)));
            v.push(((pretty, hex32), tokens));
        };

        for k in self.top_reads.keys() {
            push_key(k);
        }
        for k in self.top_writes.keys() {
            push_key(k);
        }
        for m in self.top_reads_by_ctx.values() {
            for k in m.keys() {
                push_key(k);
            }
        }
        for m in self.top_writes_by_ctx.values() {
            for k in m.keys() {
                push_key(k);
            }
        }

        // Sort and merge display-collisions.
        v.sort();
        v.dedup_by(|a, b| {
            if a.0 == b.0 {
                a.1 = merge_tokens(&a.1, &b.1);
                true
            } else {
                false
            }
        });

        println!("Legend per context [Init Inh Sig Root Fin]: R=read, W=write, -=none");
        for ((k1, k2), tokens) in v {
            // 14 = "RW RW RW RW RW"
            println!("{:<14} {:56} {}", tokens, k1, k2);
        }
    }
}
