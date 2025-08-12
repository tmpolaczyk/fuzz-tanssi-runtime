use sp_core::Hasher;
use sp_state_machine::{
    Backend, BackendTransaction, IterArgs, StateMachineStats, StorageIterator, StorageKey,
    StorageValue, TrieBackendStorage, UsageInfo,
};
use sp_storage::{ChildInfo, StateVersion, Storage};
use std::ops::Bound::{Excluded, Included, Unbounded};
use trie_db::{DBValue, MerkleValue};

pub struct SimpleBackend {
    base: &'static Storage,
}

impl SimpleBackend {
    pub fn new(base: &'static Storage) -> Self {
        Self { base }
    }
}

impl core::fmt::Debug for SimpleBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SimpleBackend")
    }
}

pub struct NoTrieBackendStorage;

impl<H: Hasher> TrieBackendStorage<H> for NoTrieBackendStorage {
    fn get(
        &self,
        key: &H::Out,
        prefix: (&[u8], std::option::Option<u8>),
    ) -> Result<Option<DBValue>, sp_state_machine::DefaultError> {
        todo!()
    }
}

#[derive(Debug)]
enum IterState {
    Pending,
    FinishedComplete,
    FinishedIncomplete,
}

#[derive(Debug)]
pub struct SimpleBackendRawIter {
    /// The prefix of the keys over which to iterate.
    prefix: Vec<u8>,
    /// (key, skip)
    /// If true, will use range bound excluded, if false will use range bound included
    key_next: Option<(Vec<u8>, bool)>,
    stop_on_incomplete_database: bool,
    child_info: Option<ChildInfo>,
    state: IterState,
}

impl<H: Hasher> StorageIterator<H> for SimpleBackendRawIter {
    type Backend = SimpleBackend;
    type Error = String;

    fn next_key(&mut self, backend: &Self::Backend) -> Option<Result<StorageKey, Self::Error>> {
        <SimpleBackendRawIter as StorageIterator<H>>::next_pair(self, backend)
            .map(|r| r.map(|(k, _)| k))
    }

    fn next_pair(
        &mut self,
        backend: &Self::Backend,
    ) -> Option<Result<(StorageKey, StorageValue), Self::Error>> {
        //println!("next_pair: {:?}", self);
        if !matches!(self.state, IterState::Pending) {
            return None;
        }

        if self.key_next.is_none() {
            // Iterator ended. To iterate over all the keys, use Some(vec![]) instead of None
            self.state = IterState::FinishedComplete;
            return None;
        }

        // next_pair: SimpleBackendRawIter { stop_on_incomplete_database: false, skip_if_first: None, child_info: None, trie_iter: (), state: Pending }
        let range_bound_start = if self.key_next.as_ref().map(|(k, v)| *v).unwrap() {
            // true = skip
            Excluded(self.key_next.clone().unwrap().0)
        } else {
            // false = not skip
            Included(self.key_next.clone().unwrap().0)
        };
        let mut iter_range = backend.base.top.range((range_bound_start, Unbounded));
        let (k, v) = match iter_range.next() {
            Some((k, v)) => (k, v),
            None => {
                self.state = IterState::FinishedComplete;
                return None;
            }
        };

        if !k.starts_with(&self.prefix) {
            // Key does not start with prefix, so we are done
            self.state = IterState::FinishedComplete;
            return None;
        }

        // And update prefix to the current key excluded bound
        self.key_next = Some((k.clone(), true));

        return Some(Ok((k.to_vec(), v.to_vec())));
    }

    fn was_complete(&self) -> bool {
        matches!(self.state, IterState::FinishedComplete)
    }
}

impl<H: Hasher> Backend<H> for SimpleBackend {
    type Error = String;
    type TrieBackendStorage = NoTrieBackendStorage;
    type RawIter = SimpleBackendRawIter;

    fn storage(&self, key: &[u8]) -> Result<Option<StorageValue>, Self::Error> {
        Ok(self.base.top.get(key).cloned())
    }

    fn storage_hash(&self, key: &[u8]) -> Result<Option<H::Out>, Self::Error> {
        Ok(<SimpleBackend as Backend<H>>::storage(self, key)?.map(|v| H::hash(&v)))
    }

    fn closest_merkle_value(&self, key: &[u8]) -> Result<Option<MerkleValue<H::Out>>, Self::Error> {
        todo!()
    }

    fn child_closest_merkle_value(
        &self,
        child_info: &ChildInfo,
        key: &[u8],
    ) -> Result<Option<MerkleValue<H::Out>>, Self::Error> {
        todo!()
    }

    fn child_storage(
        &self,
        child_info: &ChildInfo,
        key: &[u8],
    ) -> Result<Option<StorageValue>, Self::Error> {
        todo!()
    }

    fn child_storage_hash(
        &self,
        child_info: &ChildInfo,
        key: &[u8],
    ) -> Result<Option<H::Out>, Self::Error> {
        todo!()
    }

    fn next_storage_key(&self, key: &[u8]) -> Result<Option<StorageKey>, Self::Error> {
        Ok(self
            .base
            .top
            .range::<[u8], _>((Excluded(key), Unbounded))
            .next()
            .map(|(k, _)| k.to_vec()))
    }

    fn next_child_storage_key(
        &self,
        child_info: &ChildInfo,
        key: &[u8],
    ) -> Result<Option<StorageKey>, Self::Error> {
        todo!()
    }

    fn storage_root<'a>(
        &self,
        delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
        state_version: StateVersion,
    ) -> (H::Out, BackendTransaction<H>)
    where
        H::Out: Ord,
    {
        todo!()
    }

    fn child_storage_root<'a>(
        &self,
        child_info: &ChildInfo,
        delta: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)>,
        state_version: StateVersion,
    ) -> (H::Out, bool, BackendTransaction<H>)
    where
        H::Out: Ord,
    {
        todo!()
    }

    fn raw_iter(&self, args: IterArgs) -> Result<Self::RawIter, Self::Error> {
        /*
        let root = if let Some(child_info) = args.child_info.as_ref() {
            let root = match self.child_root(&child_info)? {
                Some(root) => root,
                None => return Ok(Default::default()),
            };
            root
        } else {
            self.root
        };

        if self.root == Default::default() {
            // A special-case for an empty storage root.
            return Ok(Default::default())
        }
         */

        /*
           let prefix = args.prefix.as_deref().unwrap_or(&[]);
           if let Some(start_at) = args.start_at {
               TrieDBRawIterator::new_prefixed_then_seek(db, prefix, &start_at)
           } else {
               TrieDBRawIterator::new_prefixed(db, prefix)
           }

        */

        Ok(SimpleBackendRawIter {
            stop_on_incomplete_database: args.stop_on_incomplete_database,
            child_info: args.child_info,
            prefix: args.prefix.map(|x| x.to_vec()).unwrap_or(vec![]),
            key_next: Some((
                args.start_at
                    .map(|key| key.to_vec())
                    .unwrap_or_else(|| args.prefix.map(|x| x.to_vec()).unwrap_or(vec![])),
                args.start_at_exclusive,
            )),
            state: IterState::Pending,
        })
    }

    fn register_overlay_stats(&self, _stats: &StateMachineStats) {
        todo!()
    }

    fn usage_info(&self) -> UsageInfo {
        todo!()
    }
}
