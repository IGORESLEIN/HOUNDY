use clap::Parser;
use log::{info, error};
use houndy_protocol::LdapClient;
use std::fs::File;
use std::io::Write;
use houndy_output::json::{BloodHoundJson, Meta};

mod converter;

// Use timestamp for files? Or strict names? BloodHound accepts any name if JSON structure is right.
// Standard is: <timestamp>_users.json
fn get_filename(base: &str) -> String {
    use chrono::Local;
    let now = Local::now();
    format!("{}_{}.json", now.format("%Y%m%d%H%M%S"), base)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to enumerate (e.g., corp.local)
    #[arg(short = 'd', long)]
    domain: String,

    /// Domain Controller IP/Hostname (e.g., 192.168.1.10)
    #[arg(short = 'c', long = "dc")]
    dc: String,

    /// Username for authentication
    #[arg(short = 'u', long)]
    username: String,

    /// Password for authentication
    #[arg(short = 'p', long)]
    password: String,

    /// Protocol (adws, ldaps, ldap) - Default: ldaps (auto-fallback implemented)
    #[arg(long, default_value = "ldaps")]
    proto: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting Houndy - Target: {}", args.domain);

    #[cfg(target_os = "windows")]
    {
        info!("Initializing Evasion Module...");
        // houndy_evasion::init();
    }

    // Connect with retry logic (LDAPS -> LDAP+NTLM)
    info!("Connecting to DC: {}", args.dc);
    let mut client = match LdapClient::connect_with_retry(
        &args.domain, 
        &args.dc, 
        &args.username, 
        &args.password
    ).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect and authenticate: {}", e);
            return Ok(());
        }
    };

    // Determine Base DN from Domain
    let base_dn = args.domain.split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<String>>()
        .join(",");
    info!("Using Base DN: {}", base_dn);

    use std::collections::HashMap;
    let mut sid_map: HashMap<String, String> = HashMap::new();

    // Helper to populate map
    // We need to parse entries to get DN and SID. The converter does it, but we need it raw too.
    // Or we modify converter to return map?
    // Actually, converter consumes entries.
    // Let's iterate entries before conversion.
    // Optimally, we could refactor converter to return the map entries.
    // But iterating twice in memory is fine for typical AD sizes less than millions.
    // For large AD, we'd need streaming.
    fn populate_map(entries: &Vec<houndy_protocol::SearchEntry>, map: &mut HashMap<String, String>) {
         for entry in entries {
             let dn = crate::converter::get_str(&entry.attrs, "distinguishedName");
             let sid_bytes = crate::converter::get_bin_entry(entry, "objectSid");
             let sid = houndy_parser::sid::objectsid_to_string(&sid_bytes);
             if !dn.is_empty() && !sid.is_empty() {
                 map.insert(dn.to_uppercase(), sid);
             }
         }
    }

    // 1. Users
    info!("Enumerating Users...");
    let users_ldap = client.get_users(&base_dn).await?;
    info!("Found {} users. Converting...", users_ldap.len());
    populate_map(&users_ldap, &mut sid_map);
    let user_nodes = converter::convert_users(users_ldap, &args.domain);
    save_json("users", user_nodes, &args.domain)?;

    // 2. Computers
    info!("Enumerating Computers...");
    let computers_ldap = client.get_computers(&base_dn).await?;
    info!("Found {} computers. Converting...", computers_ldap.len());
    populate_map(&computers_ldap, &mut sid_map);
    let computer_nodes = converter::convert_computers(computers_ldap, &args.domain);
    save_json("computers", computer_nodes, &args.domain)?;

    // 3. Groups
    info!("Enumerating Groups...");
    let groups_ldap = client.get_groups(&base_dn).await?;
    info!("Found {} groups. Converting...", groups_ldap.len());
    // Also add groups to map? Nested groups!
    populate_map(&groups_ldap, &mut sid_map);
    
    let group_nodes = converter::convert_groups(groups_ldap, &args.domain, &sid_map);
    save_json("groups", group_nodes, &args.domain)?;

    info!("Enumeration Complete!");
    Ok(())
}

fn save_json(type_: &str, nodes: Vec<houndy_output::json::Node>, domain: &str) -> anyhow::Result<()> {
    // Generate Meta
    let meta = Meta {
        methods: 0,
        type_: type_.to_string(), // users, computers, groups
        count: nodes.len() as u32,
        version: 4, // BloodHound v4 compatible
    };

    let output = BloodHoundJson {
        data: nodes,
        meta,
    };

    let filename = get_filename(type_);
    let file = File::create(&filename)?;
    serde_json::to_writer_pretty(file, &output)?;
    info!("Saved {} to {}", type_, filename);

    Ok(())
}
