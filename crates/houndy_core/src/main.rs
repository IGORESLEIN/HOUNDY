use clap::Parser;
use log::{info, error};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to enumerate
    #[arg(short, long)]
    domain: Option<String>,

    /// Domain Controller IP/Hostname
    #[arg(short, long)]
    dc: Option<String>,

    /// Force specific protocol (adws, ldaps, ldap)
    #[arg(long)]
    proto: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting Houndy...");

    #[cfg(target_os = "windows")]
    {
        info!("Initializing Evasion Module...");
        // houndy_evasion::init();
    }

    Ok(())
}
