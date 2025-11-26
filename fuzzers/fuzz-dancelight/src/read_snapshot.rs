use super::*;
use crate::genesis::invulnerables_from_seeds;
use crate::without_storage_root::WithoutStorageRoot;

pub fn read_snapshot(
    chain_spec_json_bytes: &[u8],
) -> (MemoryDB<BlakeTwo256>, H256, SharedTrieCache<BlakeTwo256>) {
    use serde::Deserialize;
    use sp_runtime::BuildStorage;

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

    let x: XXX1 = serde_json::from_slice(chain_spec_json_bytes).unwrap();
    let top = x
        .genesis
        .raw
        .top
        .into_iter()
        .map(|(k, v)| {
            // Need to skip 0x when decoding
            (hex::decode(&k[2..]).unwrap(), hex::decode(&v[2..]).unwrap())
        })
        .collect();

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
        .chain(accounts_with_ed.iter().cloned().map(|k| {
            (
                k,
                dancelight_runtime_constants::currency::EXISTENTIAL_DEPOSIT,
            )
        }));

    // Create empty MemoryDB
    let (mut storage, root): (MemoryDB<BlakeTwo256>, _) = GenericMemoryDB::default_with_root();

    let mut overlay = Default::default();
    //let cache_provider = trie_cache::CacheProvider::new();
    let shared_cache = SharedTrieCache::new(CacheSize::new(400_000), None);
    let cache = shared_cache.local_cache_untrusted();
    let mut backend: TrieBackend<_, BlakeTwo256> =
        TrieBackendBuilder::new_with_cache(storage, root, cache).build();

    let extensions = None;
    let mut ext = Ext::new(&mut overlay, &backend, extensions);

    sp_externalities::set_and_run_with_externalities(&mut ext, move || {
        // Initialize genesis keys
        for (k, v) in t.top {
            unhashed::put_raw(&k, &v);
        }

        // Need to manually update balances because using genesis builder overwrites total issuance
        for (account, new_balance) in genesis_balances {
            dancelight_runtime::Balances::force_set_balance(
                RuntimeOrigin::root(),
                account.into(),
                new_balance,
            )
            .unwrap();
        }

        // Remove sudo key from storage
        // This is to simplify the fuzzer: we already support root origin directly
        // As an alternative we could filter out the calls for pallet_sudo, but this way we see some
        // coverage in that pallet at least
        dancelight_runtime::Sudo::remove_key(RuntimeOrigin::root()).unwrap();
    });

    drop(ext);

    create_storage(overlay, backend, root, shared_cache)
}
