use bitflags::bitflags;
use std::fmt;

/// Structure for LDAPSID network packet.
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861>
#[derive(Clone, Debug)]
pub struct LdapSid {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: LdapSidIdentifiedAuthority,
    pub sub_authority: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct LdapSidIdentifiedAuthority {
    pub value: Vec<u8>,
}

impl LdapSidIdentifiedAuthority {
    pub fn parse(i: &[u8]) -> nom::IResult<&[u8], LdapSidIdentifiedAuthority>
    {
        use nom::bytes::streaming::take;
        let (i, value) = take(6_usize)(i)?;
        let sid_authority = LdapSidIdentifiedAuthority {
            value: value.to_vec(),
        };
        Ok((i, sid_authority))
    }
}

impl LdapSid {
    pub fn parse(i: &[u8]) -> nom::IResult<&[u8], LdapSid>
    {
        use nom::number::complete::{le_u8, le_u32};
        use nom::multi::count;

        let (i, revision) = le_u8(i)?;
        let (i, sub_authority_count) = le_u8(i)?;
        let (i, identifier_authority) = LdapSidIdentifiedAuthority::parse(i)?;
        let (i, sub_authority) = count(le_u32, sub_authority_count as usize)(i)?;

        let ldap_sid = LdapSid {
            revision,
            sub_authority_count,
            identifier_authority,
            sub_authority: sub_authority.to_vec(),
        };
        Ok((i, ldap_sid))
    }
}

/// Function to make SID String from ldap_sid struct
pub fn sid_maker(sid: &LdapSid, domain: &str) -> String {
    let mut sub = String::new();
    for v in &sid.sub_authority {
        sub.push('-');
        sub.push_str(&v.to_string());
    }

    let mut result = format!("S-{}-{}", sid.revision, sid.identifier_authority.value[5]);
    result.push_str(&sub);

    // If it's a short SID (like S-1-5-xxx), we prepend the domain if valid? 
    // RustHound logic: if length <= 16, prepend domain. 
    // This is weird heuristic but we follow it for parity.
    // Actually standard SIDs are usually longer.
    
    // NOTE: RustHound prepends domain name if SID is short?? 
    // "S-1-5-21-..." is long. "S-1-5-18" is short.
    // If it is a relative SID, maybe. 
    // I'll stick to returning the SID string itself usually.
    
    if result.len() <= 16 && !domain.is_empty() {
        format!("{}-{}", domain.to_uppercase(), result)
    } else {
        result
    }
}

/// Helper to decode binary objectSid to string
pub fn objectsid_to_string(raw: &[u8]) -> String {
     match LdapSid::parse(raw) {
         Ok((_, sid)) => sid_maker(&sid, ""),
         Err(_) => "".to_string(),
     }
}
