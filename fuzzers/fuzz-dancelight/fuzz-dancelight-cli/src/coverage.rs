pub fn execute_corpus(fuzz_target_name: &str, fuzz_main: fn(&[u8])) {
    use {
        indicatif::{ParallelProgressIterator, ProgressStyle},
        rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
        std::collections::HashSet,
    };

    let mut corpus_path = env!("CARGO_MANIFEST_DIR").to_string();
    corpus_path.push_str("/../fuzz/corpus/");
    corpus_path.push_str(fuzz_target_name);
    println!("corpus path: {:?}", corpus_path);
    let mut seen_paths = HashSet::new();
    let mut i = 0;
    // Process new entries until we catch up with the fuzzer
    // First iteration will process all entries
    // Second iteration will only process new entries
    loop {
        i += 1;
        let entries: Vec<_> = std::fs::read_dir(&corpus_path)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to read corpus path {:?}, error: {:?}",
                    corpus_path, e
                )
            })
            .filter_map(|entry| {
                if entry.is_ok() && seen_paths.contains(&entry.as_ref().unwrap().path()) {
                    None
                } else {
                    Some(entry)
                }
            })
            .collect();
        println!("iteration {} new entries: {}", i, entries.len());

        if entries.is_empty() {
            break;
        }

        let style = ProgressStyle::with_template("[{elapsed_precise}] ETA: [{eta_precise}] {bar:40.cyan/blue} {percent}% {pos:>7}/{len:7} {msg}").unwrap();
        entries
            .par_iter()
            .progress_with_style(style)
            .for_each(|entry| {
                if entry.is_err() {
                    return;
                }
                let entry = entry.as_ref().unwrap();
                let data = std::fs::read(entry.path());
                if data.is_err() {
                    return;
                }
                let data = data.unwrap();
                fuzz_main(&data);
            });

        seen_paths.extend(
            entries
                .into_iter()
                .filter_map(|entry| entry.ok().map(|entry| entry.path())),
        );
    }
}
