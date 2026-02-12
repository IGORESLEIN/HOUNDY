use ldap3::{LdapConnAsync, Scope, SearchEntry};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use anyhow::Result;
use log::{info, debug};

pub struct LdapClient {
    conn: LdapConnAsync,
}

impl LdapClient {
    /// Connects to the DC via LDAPS (Port 636)
    pub async fn connect(url: &str) -> Result<Self> {
        info!("Connecting to LDAPS: {}", url);
        // "ldaps://" URL is expected
        let (conn, _ldap) = LdapConnAsync::new(url).await?;
        Ok(LdapClient { conn })
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
        self.conn.with_controls(sd_control);

        // 2. Configure Paging Adapters
        let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(500)), // Request 500 at a time
        ];

        // 3. Perform Streaming Search
        let mut search = self.conn.streaming_search_with(
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
            if let Some(e) = SearchEntry::construct(result) {
                all_entries.push(e);
            }
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
