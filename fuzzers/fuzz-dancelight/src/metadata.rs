use dancelight_runtime::Runtime;
use frame_metadata::v15::RuntimeMetadataV15;
use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
use lazy_static::lazy_static;
use parity_scale_codec::Decode;
use scale_info::PortableRegistry;
use std::collections::HashMap;

lazy_static::lazy_static! {
    pub static ref METADATA: RuntimeMetadataV15 = {
        let metadata_bytes = &Runtime::metadata_at_version(15)
            .expect("Metadata must be present; qed");

        let metadata: RuntimeMetadataPrefixed =
            Decode::decode(&mut &metadata_bytes[..]).expect("Metadata encoded properly; qed");

        let metadata: RuntimeMetadataV15 = match metadata.1 {
            RuntimeMetadata::V15(metadata) => metadata,
            _ => panic!("metadata has been bumped, test needs to be updated"),
        };

        for x in &metadata.types.types {
            let path = x.ty.path.to_string();
            log::info!("id: {} type: {}", x.id, path);
        }

        metadata
    };

    pub static ref RUNTIME_API_NAMES: Vec<String> = {
        let mut v = vec![];

        for api in METADATA.apis.iter() {
            for method in api.methods.iter() {
                v.push(format!("{}_{}", api.name, method.name));
            }
        }

        v.sort();

        v
    };

    pub static ref RUNTIME_CALL_TYPE_ID: u32 = {
        find_type_id(&METADATA.types, "RuntimeCall")
    };

    pub static ref ACCOUNT_ID_TYPE_ID: u32 = {
        find_type_id(&METADATA.types, "AccountId")
    };

    /// twox128(pallet_storage_prefix) -> pallet_name
    pub static ref PALLET_PREFIX_TO_NAME: HashMap<[u8; 16], String> = {
        let meta: &RuntimeMetadataV15 = &*METADATA;
        let mut m = HashMap::new();

        for pallet in &meta.pallets {
            if let Some(storage) = &pallet.storage {
                let h = sp_core::hashing::twox_128(storage.prefix.as_bytes());
                if let Some(prev) = m.insert(h, pallet.name.clone()) {
                    panic!(
                        "twox128 collision for pallet storage prefix: hash {} used by '{}' and '{}'",
                        hex::encode(&h), prev, pallet.name
                    );
                }
            }
        }
        m
    };

    /// twox128(pallet_prefix) ++ twox128(storage_name) -> (pallet_name, storage_name)
    pub static ref STORAGE_PREFIX_TO_NAMES: HashMap<[u8; 32], (String, String)> = {
        let meta: &RuntimeMetadataV15 = &*METADATA;
        let mut m = HashMap::new();

        for pallet in &meta.pallets {
            if let Some(storage) = &pallet.storage {
                let pallet_hash = sp_core::hashing::twox_128(storage.prefix.as_bytes());
                for entry in &storage.entries {
                    let entry_hash = sp_core::hashing::twox_128(entry.name.as_bytes());
                    let mut key = [0u8; 32];
                    key[..16].copy_from_slice(&pallet_hash);
                    key[16..].copy_from_slice(&entry_hash);

                    if let Some(prev) = m.insert(key, (pallet.name.clone(), entry.name.clone())) {
                        panic!(
                            "twox128 collision for storage prefix: hash {} used by '{:?}' and '{:?}'",
                            hex::encode(&key),
                            prev,
                            (pallet.name.clone(), entry.name.clone())
                        );
                    }
                }
            }
        }
        m
    };
}

/// Helper: get pallet name from a raw storage key (first 16 bytes).
pub fn pallet_name_from_key(key: &[u8]) -> Option<&'static str> {
    if key.len() < 16 {
        return None;
    }
    let mut pfx = [0u8; 16];
    pfx.copy_from_slice(&key[..16]);
    PALLET_PREFIX_TO_NAME.get(&pfx).map(|s| s.as_str())
}

/// Helper: get (pallet, storage) from a raw storage key (first 32 bytes).
pub fn storage_names_from_key(key: &[u8]) -> Option<(&'static str, &'static str)> {
    if key.len() < 32 {
        return None;
    }
    let mut pfx = [0u8; 32];
    pfx.copy_from_slice(&key[..32]);
    STORAGE_PREFIX_TO_NAMES
        .get(&pfx)
        .map(|(p, s)| (p.as_str(), s.as_str()))
}

/// Returns Some(&str) if `bytes` are printable ASCII; otherwise None.
/// "Printable" = ASCII graphic chars plus space/tab/newline/CR.
/// Useful to show human-friendly keys when they were stored as plain text.
pub fn ascii_str_if_printable(bytes: &[u8]) -> Option<&str> {
    let printable = bytes.iter().all(|&b| is_printable_ascii(b));

    if printable {
        // SAFETY: printable ASCII is valid UTF-8
        Some(std::str::from_utf8(bytes).unwrap())
    } else {
        None
    }
}

fn is_printable_ascii(b: u8) -> bool {
    // graphic ASCII (0x21..=0x7E)
    b.is_ascii_graphic()
        // plus common whitespace
        || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Returns Some(&str) with the *leading* printable-ASCII prefix, or None if the first byte isn't printable.
pub fn ascii_prefix_if_printable(bytes: &[u8], min_len: usize) -> Option<&str> {
    let len = bytes.iter().take_while(|&&b| is_printable_ascii(b)).count();
    if len == 0 || len < min_len {
        return None;
    }
    // SAFETY: we only included ASCII bytes which are valid UTF-8.
    Some(std::str::from_utf8(&bytes[..len]).unwrap())
}

pub fn unhash_storage_key(key: &[u8]) -> String {
    if let Some((pallet_name, storage_name)) = storage_names_from_key(key) {
        format!("{} {}", pallet_name, storage_name)
    } else if let Some(pallet_name) = pallet_name_from_key(key) {
        format!("{} {}", pallet_name, "<unknown>")
    } else if let Some(ascii_str) = ascii_str_if_printable(key) {
        // debug-escape so it is clear that this is a raw key (it will start with ")
        format!("{:?}", ascii_str)
    } else if let Some(ascii_str) = ascii_prefix_if_printable(key, 3) {
        format!("{:?}...", ascii_str)
    } else {
        format!("<unknown>")
    }
}

fn find_type_id(registry: &PortableRegistry, path_contains: &str) -> u32 {
    let type_id = registry.types.iter().filter_map(|x| {
        let path = x.ty.path.to_string();
        if path.contains(path_contains) {
            Some(x.id)
        } else {
            None
        }
    });
    let found: Vec<u32> = type_id.collect();
    assert_eq!(
        found.len(),
        1,
        "Couldn't find type id or found more than 1 type"
    );

    found.into_iter().next().unwrap()
}
