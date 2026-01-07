use sp_externalities::{Error, Extension, ExtensionStore, Externalities, MultiRemovalResults};
use sp_storage::{ChildInfo, StateVersion, TrackedStorageKey};
use std::any::{Any, TypeId};

/// Wrap externalities and return fake storage root based on block number
pub struct WithoutStorageRoot<T> {
    inner: T,
}

impl<T> WithoutStorageRoot<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: ExtensionStore> ExtensionStore for WithoutStorageRoot<T> {
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

impl<T: Externalities> Externalities for WithoutStorageRoot<T> {
    fn set_offchain_storage(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.inner.set_offchain_storage(key, value)
    }

    fn storage(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.storage(key)
    }

    fn storage_hash(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.storage_hash(key)
    }

    fn child_storage_hash(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.child_storage_hash(child_info, key)
    }

    fn child_storage(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.child_storage(child_info, key)
    }

    fn next_storage_key(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.next_storage_key(key)
    }

    fn next_child_storage_key(&mut self, child_info: &ChildInfo, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.next_child_storage_key(child_info, key)
    }

    fn kill_child_storage(
        &mut self,
        child_info: &ChildInfo,
        maybe_limit: Option<u32>,
        maybe_cursor: Option<&[u8]>,
    ) -> MultiRemovalResults {
        self.inner
            .kill_child_storage(child_info, maybe_limit, maybe_cursor)
    }

    fn clear_prefix(
        &mut self,
        prefix: &[u8],
        maybe_limit: Option<u32>,
        maybe_cursor: Option<&[u8]>,
    ) -> MultiRemovalResults {
        self.inner.clear_prefix(prefix, maybe_limit, maybe_cursor)
    }

    fn clear_child_prefix(
        &mut self,
        child_info: &ChildInfo,
        prefix: &[u8],
        maybe_limit: Option<u32>,
        maybe_cursor: Option<&[u8]>,
    ) -> MultiRemovalResults {
        self.inner
            .clear_child_prefix(child_info, prefix, maybe_limit, maybe_cursor)
    }

    fn place_storage(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        self.inner.place_storage(key, value)
    }

    fn place_child_storage(
        &mut self,
        child_info: &ChildInfo,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) {
        self.inner.place_child_storage(child_info, key, value)
    }

    fn storage_root(&mut self, _state_version: StateVersion) -> Vec<u8> {
        // Mock storage root using block number
        // This is an attempt to make the fuzzer faster
        let block_number = self
            .inner
            .storage(&hex_literal::hex!(
                "26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac"
            ))
            .unwrap();
        assert_eq!(block_number.len(), 4);

        let mut mocked: Vec<u8> = format!("__FUZZ_MOCK_STORAGE_ROOT_").into();
        mocked.extend(block_number);
        assert!(mocked.len() <= 32);

        let mut x = vec![0u8; 32];

        x[0..mocked.len()].copy_from_slice(&mocked);

        x
    }

    fn child_storage_root(
        &mut self,
        child_info: &ChildInfo,
        state_version: StateVersion,
    ) -> Vec<u8> {
        // TODO: also mock this one if used
        todo!()
    }

    fn storage_append(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.inner.storage_append(key, value)
    }

    fn storage_start_transaction(&mut self) {
        self.inner.storage_start_transaction()
    }

    fn storage_rollback_transaction(&mut self) -> Result<(), ()> {
        self.inner.storage_rollback_transaction()
    }

    fn storage_commit_transaction(&mut self) -> Result<(), ()> {
        self.inner.storage_commit_transaction()
    }

    fn wipe(&mut self) {
        self.inner.wipe()
    }

    fn commit(&mut self) {
        self.inner.commit()
    }

    fn read_write_count(&self) -> (u32, u32, u32, u32) {
        self.inner.read_write_count()
    }

    fn reset_read_write_count(&mut self) {
        self.inner.reset_read_write_count()
    }

    fn get_whitelist(&self) -> Vec<TrackedStorageKey> {
        self.inner.get_whitelist()
    }

    fn set_whitelist(&mut self, new: Vec<TrackedStorageKey>) {
        self.inner.set_whitelist(new)
    }

    fn get_read_and_written_keys(&self) -> Vec<(Vec<u8>, u32, u32, bool)> {
        self.inner.get_read_and_written_keys()
    }
}
