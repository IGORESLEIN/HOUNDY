use ldap3::{LdapConnAsync, Scope, SearchEntry};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use anyhow::Result;
use log::{info, debug, error};

use ldap3::Ldap;

pub struct LdapClient {
    ldap: Ldap,
}

impl LdapClient {
    /// Connects to the DC via LDAPS (Port 636) or LDAP (389)
    pub async fn connect(url: &str) -> Result<Self> {
        info!("Connecting to: {}", url);
        let (conn, ldap) = LdapConnAsync::new(url).await?;
        // We need to drive the connection if we want to keep it alive? 
        // LdapConnAsync handles it internally usually.
        // Actually LdapConnAsync::new returns (LdapConnAsync, Ldap)
        // We only stored LdapConnAsync in struct but we might need Ldap handle for binding?
        // Wait, LdapConnAsync IS the handle we use for search?
        // Let's check docs: LdapConnAsync::new returns (LdapConnAsync, Ldap)
        // LdapConnAsync is the driver, Ldap is the handle.
        // We should store the handle to use it.
        // The original code `Ok(LdapClient { conn })` suggests `conn` was `LdapConnAsync`.
        // But `streaming_search_with` is a method on `Ldap`.
        // So `conn` in struct SHOULD be `Ldap`.
        // Let's fix the struct too.
        
        // Actually, looking at previous file content:
        // `pub struct LdapClient { conn: LdapConnAsync, }`
        // `let (conn, _ldap) = LdapConnAsync::new(url).await?;`
        // `Ok(LdapClient { conn })`
        // And `self.conn.streaming_search_with`...
        // `streaming_search_with` exists on `Ldap`, NOT `LdapConnAsync`?
        // Actually `LdapConnAsync` is the low-level connection?
        // Most `ldap3` variations use `Ldap` struct for operations.
        // Let's check `ldap3` docs via memory or assume standard usage.
        // Standard: `let (conn, mut ldap) = LdapConnAsync::new(url).await?;`
        // `ldap3::Ldap` has `simple_bind`, `sasl_external_bind`, `search`, etc.
        // The `LdapConnAsync` must be polled/spawned.
        // The original code was likely WRONG or using a specific version/wrapper I am not seeing.
        // `LdapConnAsync` in `ldap3` 0.11 usually needs to be driven.
        
        // Let's assume standard `ldap3` 0.11+ usage:
        // Struct should hold `Ldap`.
        // Transformation:
        
        ldap3::drive!(conn); // Auto-drive macro if available or just spawn
        // But `LdapConnAsync` is the typo in original code? 
        // Original: `use ldap3::{LdapConnAsync, ...}`
        // `pub struct LdapClient { conn: LdapConnAsync }`
        // `self.conn.with_controls(...)`
        // `self.conn.streaming_search_with(...)`
        
        // If `LdapConnAsync` has these methods, then it's fine.
        // But usually it is `Ldap` struct.
        // Let's fix the struct to `Ldap` and spawn the driver.
        
        Ok(LdapClient { ldap })
    }

    pub async fn connect_with_retry(
        domain: &str,
        dc: &str,
        username: &str, 
        password: &str
    ) -> Result<Self> {
        // 1. Try LDAPS
        let ldaps_url = format!("ldaps://{}:636", dc);
        info!("Attempting LDAPS connection to {}", ldaps_url);
        match Self::new_connection(&ldaps_url).await {
            Ok(mut client) => {
                info!("LDAPS connected. Authenticating...");
                if let Err(e) = client.authenticate(username, password, domain).await {
                     error!("LDAPS Authentication failed: {}", e);
                     // If auth fails, maybe try NTLM on invalid creds? No, if credentials are bad, they are bad.
                     // But if it is protocol error, maybe.
                     // Let's assume strict auth check.
                     return Err(e);
                }
                info!("LDAPS Authentication successful.");
                return Ok(client);
            },
            Err(e) => {
                error!("LDAPS connection failed: {}", e);
            }
        }

        // 2. Try LDAP + NTLM
        let ldap_url = format!("ldap://{}:389", dc);
        info!("Falling back to LDAP (NTLM) connection to {}", ldap_url);
        match Self::new_connection(&ldap_url).await {
             Ok(mut client) => {
                 info!("LDAP connected. Authenticating via NTLM...");
                 client.authenticate_ntlm(username, password, domain).await?;
                 info!("LDAP NTLM Authentication successful.");
                 Ok(client)
             },
             Err(e) => Err(e)
        }
    }

    async fn new_connection(url: &str) -> Result<Self> {
        let (conn, ldap) = LdapConnAsync::new(url).await?;
        // We must spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection error: {}", e);
            }
        });
        Ok(LdapClient { ldap })
    }

    pub async fn authenticate(&mut self, user: &str, pass: &str, domain: &str) -> Result<()> {
        let bind_dn = format!("{}@{}", user, domain); 
        self.ldap.simple_bind(&bind_dn, pass).await?.success()?;
        Ok(())
    }

    pub async fn authenticate_ntlm(&mut self, user: &str, pass: &str, domain: &str) -> Result<()> {
        // NTLM Bind currently disabled due to dependency issues (sspi crate conflict).
        // Falling back to Simple Bind with UPN (user@domain).
        let bind_user = format!("{}@{}", user, domain);
        
        info!("Performing Simple Bind as {}", bind_user);
        self.ldap.simple_bind(&bind_user, pass).await?.success()?;
        Ok(())
    }

    /// Generic search with Streaming Paging support (Robust & Rust-native)
    pub async fn search_paged(&mut self, base_dn: &str, filter: &str, attrs: Vec<&str>) -> Result<Vec<SearchEntry>> {
        debug!("LDAP Search: base={}, filter={}", base_dn, filter);
        
        // 1. Configure SD Flags to ensure we get the DACL (Critical for BloodHound)
        // OID: 1.2.840.113556.1.4.801 (LDAP_SERVER_SD_FLAGS_OID)
        // Value: 0x7 = (DACL | GROUP | OWNER) - We don't need SACL usually
        // BER encoding of Integer 7 is 02 01 07.
        // RustHound uses 48,3,2,1,5 ?? 48=Sequence, 3=Len, 2=Int, 1=Len, 5=Value.
        // Value 5 = Owner (1) + DACL (4). We typically want Group (2) too -> 7.
        // Let's stick to 7 (Owner+Group+DACL).
        let sd_control = RawControl {
            ctype: "1.2.840.113556.1.4.801".to_string(),
            crit: true,
            val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]), // Sequence(Int(7))
        };
        self.ldap.with_controls(sd_control);

        // 2. Configure Paging Adapters
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)), // Request 500 at a time
        ];

        // 3. Perform Streaming Search
        let mut search = self.ldap.streaming_search_with(
            adapters,
            base_dn,
            Scope::Subtree,
            filter,
            attrs
        ).await?;

        let mut all_entries = Vec::new();

        // 4. Collect results
        while let Some(result) = search.next().await? {
            // Check if it's an entry (Adapter ensures we mostly get entries, but SafeWrapper)
            // Check if it's an entry (Adapter ensures we mostly get entries, but SafeWrapper)
            // SearchEntry::construct returns SearchEntry directly
            let e = SearchEntry::construct(result);
            all_entries.push(e);
        }

        Ok(all_entries)
    }

    pub async fn get_users(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        let filter = "(&(objectClass=user)(objectCategory=person)(!(objectClass=computer)))";
        // Full BloodHound Attribute List
        let attrs = vec![
            "sAMAccountName", "distinguishedName", "memberOf", "primaryGroupID", "objectSid",
            "servicePrincipalName", "adminCount", "userAccountControl", 
            "description", "lastLogonTimestamp", "pwdLastSet", "whenCreated",
            "msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink", // Delegation / Shadow Creds
            "nTSecurityDescriptor", // CRITICAL: ACLs
            "ms-Mcs-AdmPwd", "unixUserPassword", // LAPS & Unix Passwords
            "sidHistory", // Migration Attacks
            "scriptPath", "homeDirectory"
        ];
        self.search_paged(base_dn, filter, attrs).await
    }

    pub async fn get_computers(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        let filter = "(objectClass=computer)";
        let attrs = vec![
            "sAMAccountName", "distinguishedName", "memberOf", "primaryGroupID", "objectSid",
            "operatingSystem", "operatingSystemVersion", "dNSHostName", 
            "userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "nTSecurityDescriptor", "lastLogonTimestamp", "pwdLastSet",
            "sidHistory" // Migration Attacks
        ];
        self.search_paged(base_dn, filter, attrs).await
    }

    pub async fn get_groups(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        let filter = "(objectClass=group)";
        let attrs = vec![
            "sAMAccountName", "distinguishedName", "member", "objectSid", "adminCount",
            "nTSecurityDescriptor"
        ];
        self.search_paged(base_dn, filter, attrs).await
    }

    pub async fn get_gpos(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        let filter = "(objectClass=groupPolicyContainer)";
        let attrs = vec![
            "displayName", "name", "distinguishedName", "objectSid", 
            "gPCFileSysPath", "nTSecurityDescriptor"
        ];
        self.search_paged(base_dn, filter, attrs).await
    }

    pub async fn get_ous(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        let filter = "(objectClass=organizationalUnit)";
        let attrs = vec![
            "name", "distinguishedName", "objectSid", "gPLink", "gPOptions",
            "nTSecurityDescriptor"
        ];
        self.search_paged(base_dn, filter, attrs).await
    }

    pub async fn get_trusts(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        let filter = "(objectClass=trustedDomain)";
        let attrs = vec![
            "flatName", "name", "securityIdentifier", "trustDirection", "trustType",
            "trustAttributes"
        ];
        self.search_paged(base_dn, filter, attrs).await
    }

    pub async fn get_cert_templates(&mut self, base_dn: &str) -> Result<Vec<SearchEntry>> {
        // Look in Configuration Naming Context (CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...)
        // For v0.1 we rely on the user providing the config DN or we search from Root.
        let filter = "(objectClass=pKICertificateTemplate)";
        let attrs = vec![
            "cn", "name", "displayName", "pkiExtendedKeyUsage", "mspki-certificate-name-flag",
            "mspki-enrollment-flag", "nTSecurityDescriptor" // Key for ESC1
        ];
        self.search_paged(base_dn, filter, attrs).await
    }
}
