use anyhow::Result;
use clap::{Parser, Subcommand};

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
        /// Path to the input corpus directory
        #[arg(long)]
        corpus_path: String,
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::ExecuteCorpus {
            fuzz_target,
            corpus_path,
        } => {
            // TODO: implement execute-corpus logic
            unimplemented!(
                "execute-corpus: fuzz_target={}, corpus_path={}",
                fuzz_target,
                corpus_path
            );
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
    }
}
