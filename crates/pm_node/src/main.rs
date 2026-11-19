use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use ledger_core::ProofVerifier;
use pm_node::{NodeEngine, NodeMockVerifier, PmNodeServer};
use pm_sdk::NargoBbProver;

#[derive(Parser, Debug)]
#[command(name = "pm-node", about = "Perfect Money Phase 4 HTTP/1.1 settlement and mesh node")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: String,
    #[arg(long, default_value_t = false)]
    mock_verifier: bool,
    #[arg(long, default_value = "./circuits")]
    circuits_dir: PathBuf,
    #[arg(long, default_value = "./target/pm_node_cache")]
    cache_dir: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let verifier: Box<dyn ProofVerifier + Send + Sync> = if cli.mock_verifier {
        Box::new(NodeMockVerifier)
    } else {
        let prover = NargoBbProver::new(&cli.circuits_dir, &cli.cache_dir)?;
        Box::new(prover.bb_verifier())
    };
    let engine = NodeEngine::new(verifier)?;
    let server = PmNodeServer::start(&cli.bind, engine)?;
    println!("pm-node listening on {}", server.base_url());

    let running = Arc::new(AtomicBool::new(true));
    while running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

