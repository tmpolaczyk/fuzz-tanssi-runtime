use sp_externalities::Externalities;
use sp_storage::StorageMap;
use {
    super::*,
    sp_state_machine::{OverlayedChanges, TrieMut},
    trie_db::{TrieDBMut, TrieDBMutBuilder},
};

pub fn create_storage(
    mut overlay: OverlayedChanges<BlakeTwo256>,
    backend: TrieBackend<MemoryDB<BlakeTwo256>, BlakeTwo256>,
    root: H256,
    shared_cache: SharedTrieCache<BlakeTwo256>,
) -> (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
    let changes = overlay
        .drain_storage_changes(&backend, StateVersion::V1)
        .unwrap();

    let mut storage = backend.into_storage();
    let mut cache2 = shared_cache.local_cache_untrusted();
    //let mut root_decoded: H256 = Decode::decode(&mut root1.as_slice()).unwrap();
    let mut root_mut = root.clone();
    let mut triedbmut: TrieDBMut<LayoutV1<BlakeTwo256>> =
        TrieDBMutBuilder::from_existing(&mut storage, &mut root_mut)
            .with_optional_cache(None)
            .build();

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

pub fn ext_to_simple_storage(ext: &mut dyn Externalities) -> Storage {
    let mut top = StorageMap::default();

    sp_externalities::set_and_run_with_externalities(ext, || {
        let mut prefix = vec![];
        while let Some(key) = sp_io::storage::next_key(&prefix) {
            let value = frame_support::storage::unhashed::get_raw(&key).unwrap();
            let key = key.to_vec();
            prefix = key.clone();

            top.insert(key, value);
        }
    });

    Storage {
        top,
        ..Default::default()
    }
}
