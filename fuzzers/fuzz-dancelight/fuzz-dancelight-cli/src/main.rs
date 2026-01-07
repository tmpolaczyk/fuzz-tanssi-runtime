use anyhow::{Result, anyhow};
use arbitrary::{Arbitrary, Unstructured};
use clap::{Parser, Subcommand};
use fuzz_dancelight::{
    EVENT_TRACER, EXTR_TRACER, ExtrOrPseudo, FuzzLiveOneblock, FuzzRuntimeCall, FuzzZombie,
    FuzzerConfig, STORAGE_TRACER, StorageTracer, TraceEvents, TraceStorage, example_runtime_call,
    extrinsics_iter, fuzz_decode_calls, fuzz_inbound_v2, fuzz_init, fuzz_init_only_logger,
    fuzz_live_oneblock, fuzz_zombie,
};
use notify::{Event, RecursiveMode, Watcher, recommended_watcher};
use scale_info::TypeInfo;
use scale_info::scale::Encode;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};

mod coverage;

/// CLI for fuzz-dancelight
#[derive(Parser)]
#[command(name = "fuzz-dancelight-cli")]
#[command(about = "CLI for fuzz-dancelight operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute the corpus fuzzing target
    ExecuteCorpus {
        /// The name of the fuzz target to run
        #[arg(long)]
        fuzz_target: String,
    },

    /// Execute the corpus fuzzing target
    StorageTracer {
        /// The name of the fuzz target to run
        #[arg(long)]
        fuzz_target: String,
        #[arg(long, conflicts_with = "corpus_path")]
        input_path: Option<String>,
        #[arg(long, conflicts_with = "input_path")]
        corpus_path: Option<String>,
    },

    /// Execute the corpus fuzzing target
    EventTracer {
        /// The name of the fuzz target to run
        #[arg(long)]
        fuzz_target: String,
        #[arg(long, conflicts_with = "corpus_path")]
        input_path: Option<String>,
        #[arg(long, conflicts_with = "input_path")]
        corpus_path: Option<String>,
    },

    /// Update a snapshot and output as hex
    UpdateSnapshot {
        /// Path to the input snapshot file
        #[arg(long)]
        input_snapshot_path: String,
        /// Path to write the hex-encoded snapshot
        #[arg(long)]
        output_hexsnapshot_path: String,
    },

    /// Decode a corpus input
    DecodeInput {
        #[arg(long)]
        input_path: String,
    },

    /// Decode a corpus input
    EncodeInput {},

    /// Decode a corpus input
    DecodeInputWatch {
        #[arg(long)]
        corpus_path: String,
        //#[arg(long, short = "n")]
        //interval: f32,
    },
}

fn fuzz_inbound_v2_wrapper<FC: FuzzerConfig<ExtrOrPseudo = ExtrOrPseudo>>(data: &[u8]) {
    fuzz_inbound_v2::<FC>(Arbitrary::arbitrary(&mut Unstructured::new(data)).unwrap())
}

fn init_and_get_fuzz_main(fuzz_target: &str) -> fn(&[u8]) {
    match fuzz_target {
        "fuzz_decode_calls" => fuzz_init_only_logger(),
        "fuzz_live_oneblock" => fuzz_init::<FuzzLiveOneblock>(),
        "fuzz_inbound_v2" => fuzz_init::<FuzzLiveOneblock>(),
        "fuzz_zombie" => fuzz_init::<FuzzZombie>(),
        _ => unimplemented!("unknown fuzz target {:?}", fuzz_target),
    };

    let fuzz_main = match fuzz_target {
        "fuzz_decode_calls" => fuzz_decode_calls,
        "fuzz_live_oneblock" => fuzz_live_oneblock::<FuzzLiveOneblock>,
        "fuzz_inbound_v2" => fuzz_inbound_v2_wrapper::<FuzzLiveOneblock>,
        "fuzz_zombie" => fuzz_zombie::<FuzzZombie>,
        _ => unimplemented!("unknown fuzz target {:?}", fuzz_target),
    };

    fuzz_main
}

fn init_and_get_fuzz_main_trace_storage(fuzz_target: &str) -> fn(&[u8]) {
    match fuzz_target {
        "fuzz_decode_calls" => fuzz_init_only_logger(),
        "fuzz_live_oneblock" => fuzz_init::<TraceStorage<FuzzLiveOneblock>>(),
        "fuzz_zombie" => fuzz_init::<TraceStorage<FuzzZombie>>(),
        _ => unimplemented!("unknown fuzz target {:?}", fuzz_target),
    };

    let fuzz_main = match fuzz_target {
        "fuzz_decode_calls" => fuzz_decode_calls,
        "fuzz_live_oneblock" => fuzz_live_oneblock::<TraceStorage<FuzzLiveOneblock>>,
        "fuzz_zombie" => fuzz_zombie::<TraceStorage<FuzzZombie>>,
        _ => unimplemented!("unknown fuzz target {:?}", fuzz_target),
    };

    fuzz_main
}

fn init_and_get_fuzz_main_trace_events(fuzz_target: &str) -> fn(&[u8]) {
    match fuzz_target {
        "fuzz_decode_calls" => fuzz_init_only_logger(),
        "fuzz_live_oneblock" => fuzz_init::<TraceEvents<FuzzLiveOneblock>>(),
        "fuzz_zombie" => fuzz_init::<TraceEvents<FuzzZombie>>(),
        _ => unimplemented!("unknown fuzz target {:?}", fuzz_target),
    };

    let fuzz_main = match fuzz_target {
        "fuzz_decode_calls" => fuzz_decode_calls,
        "fuzz_live_oneblock" => fuzz_live_oneblock::<TraceEvents<FuzzLiveOneblock>>,
        "fuzz_zombie" => fuzz_zombie::<TraceEvents<FuzzZombie>>,
        _ => unimplemented!("unknown fuzz target {:?}", fuzz_target),
    };

    fuzz_main
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::ExecuteCorpus { fuzz_target } => {
            let fuzz_main = init_and_get_fuzz_main(fuzz_target.as_str());
            coverage::execute_corpus(&fuzz_target, fuzz_main);
            Ok(())
        }
        Commands::StorageTracer {
            fuzz_target,
            input_path,
            corpus_path,
        } => {
            assert_eq!(input_path, None, "unimplemented");
            assert_eq!(corpus_path, None, "unimplemented");
            let fuzz_main = init_and_get_fuzz_main_trace_storage(fuzz_target.as_str());
            coverage::execute_corpus(&fuzz_target, fuzz_main);

            let storage_tracer = STORAGE_TRACER.lock().unwrap();
            storage_tracer.print_histograms();
            println!();
            storage_tracer.print_all_keys_alphabetical_by_context();

            Ok(())
        }
        Commands::EventTracer {
            fuzz_target,
            input_path,
            corpus_path,
        } => {
            assert_eq!(input_path, None, "unimplemented");
            assert_eq!(corpus_path, None, "unimplemented");
            let fuzz_main = init_and_get_fuzz_main_trace_events(fuzz_target.as_str());
            coverage::execute_corpus(&fuzz_target, fuzz_main);

            println!("EVENTS");
            let event_tracer = EVENT_TRACER.lock().unwrap();
            event_tracer.print_events();
            println!("");
            println!("SUCCESSFUL EXTRINSICS");
            let extr_tracer = EXTR_TRACER.lock().unwrap();
            extr_tracer.print_ok_extrs();

            Ok(())
        }
        Commands::UpdateSnapshot {
            input_snapshot_path,
            output_hexsnapshot_path,
        } => {
            fuzz_dancelight::update_snapshot_after_on_initialize(
                &input_snapshot_path,
                &output_hexsnapshot_path,
            );
            Ok(())
        }
        Commands::DecodeInput { input_path } => {
            let input_bytes = std::fs::read(&input_path)?;
            let extr: Vec<_> = extrinsics_iter(&input_bytes).collect();
            //println!("{:?}", extr);
            for x in extr {
                println!("{:?}", x);
            }
            Ok(())
        }
        Commands::EncodeInput {} => {
            let mut extr: Vec<ExtrOrPseudo> =
                vec![ExtrOrPseudo::Pseudo(FuzzRuntimeCall::NewBlock); 250];

            extr.push(ExtrOrPseudo::Extr(example_runtime_call()));

            let encoded: Vec<u8> = extr.iter().map(|x| x.encode()).flatten().collect();
            assert_eq!(
                extrinsics_iter(&encoded).collect::<Vec<ExtrOrPseudo>>(),
                extr
            );

            std::fs::write("encoded_input_test", encoded)?;

            Ok(())
        }

        Commands::DecodeInputWatch { corpus_path } => {
            if false {
                // Initial processing: find and decode the most recent file
                if let Some(newest) = std::fs::read_dir(&corpus_path)?
                    .filter_map(Result::ok)
                    .filter_map(|e| {
                        e.metadata()
                            .ok()
                            .and_then(|m| m.modified().ok().map(|t| (t, e.path())))
                    })
                    .max_by_key(|(t, _)| *t)
                    .map(|(_, path)| path)
                {
                    let bytes = std::fs::read(&newest)
                        .map_err(|e| anyhow!("failed to read {}: {}", newest.display(), e))?;
                    for extr in extrinsics_iter(&bytes) {
                        println!("{:?}", extr);
                    }
                }
            }

            // Watch for new files and process immediately
            let (tx, rx) = mpsc::channel();
            let mut watcher =
                recommended_watcher(tx).map_err(|e| anyhow!("failed to create watcher: {}", e))?;
            watcher
                .watch(Path::new(&corpus_path), RecursiveMode::NonRecursive)
                .map_err(|e| anyhow!("failed to watch {}: {}", corpus_path, e))?;

            for res in rx {
                let paths = match res {
                    Ok(Event { paths, .. }) => paths,
                    Err(e) => return Err(e.into()),
                };
                for path in paths {
                    if path.is_file() {
                        let bytes = std::fs::read(&path)
                            .map_err(|e| anyhow!("failed to read {}: {}", path.display(), e))?;
                        println!();
                        println!("{}", path.display());
                        for extr in extrinsics_iter(&bytes) {
                            println!("{:?}", extr);
                        }
                    }
                }
            }

            Ok(())
        }
    }
}
