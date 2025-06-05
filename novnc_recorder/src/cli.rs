use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Sets a custom config file path
    #[arg(short, long, value_name = "FILE_PATH")]
    pub config: Option<PathBuf>,

    /// Enables dry-run mode: loads config, checks paths, and exits
    #[arg(long)]
    pub dry_run: bool,
    // Add other CLI options here as needed later
    // For example:
    // /// Overrides the log level from the config file
    // #[arg(long, value_name = "LEVEL")]
    // pub log_level: Option<String>,
}

impl CliArgs {
    pub fn parse_args() -> Self {
        CliArgs::parse()
    }
}
