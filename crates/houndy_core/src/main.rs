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

use clap::Parser;
use log::{info, error};
use houndy_protocol::LdapClient;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to enumerate
    #[arg(short, long)]
    domain: Option<String>,

    /// Domain Controller IP/Hostname (e.g., ldaps://192.168.1.10)
    #[arg(short, long)]
    dc: Option<String>,

    /// Protocol (adws, ldaps, ldap) - Default: ldaps
    #[arg(long, default_value = "ldaps")]
    proto: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting Houndy - Protocol Mode: {}", args.proto);

    #[cfg(target_os = "windows")]
    {
        info!("Initializing Evasion Module...");
        // houndy_evasion::init();
    }

    if let Some(dc_url) = args.dc {
        if args.proto == "ldaps" {
            info!("Connecting to {}", dc_url);
            let mut client = LdapClient::connect(&dc_url).await?;
            
            // Default Base DN guess or strict arg? For now, hardcode example or ask user.
            // Ideally we'd fetch namingContexts from RootDSE.
            let base_dn = "DC=corp,DC=local"; // Placeholder - needs dynamic resolution

            info!("Enumerating Users...");
            let users = client.get_users(base_dn).await?;
            info!("Found {} users", users.len());
            for u in users.iter().take(5) {
                info!(" - {:?}", u.attrs.get("sAMAccountName"));
            }

            info!("Enumerating Computers...");
            let computers = client.get_computers(base_dn).await?;
            info!("Found {} computers", computers.len());
        }
    } else {
        error!("Please provide a DC URL with --dc (e.g., ldaps://dc01.corp.local:636)");
    }

    Ok(())
}
