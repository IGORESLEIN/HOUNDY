use crate::secdesc::{SecurityDescriptor, Acl, Ace};
use crate::sid::{sid_maker, LdapSid};
use serde_json::{json, Value};
use std::collections::HashMap;
use log::{trace, error};

// Constants (Masks & Flags)
pub const GENERIC_ALL: u32 = 0x10000000;
pub const WRITE_DACL: u32  = 0x00040000;
pub const WRITE_OWNER: u32 = 0x00080000;
pub const GENERIC_WRITE: u32 = 0x40000000;

// Helper to parse mask from ACE data (first 4 bytes usually)
fn get_ace_mask(data: &[u8]) -> u32 {
    if data.len() < 4 { return 0; }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Main function to parse nTSecurityDescriptor into BloodHound "Aces" list
pub fn parse_ntsecuritydescriptor(
    nt_blob: &[u8],
    domain: &str,
) -> Vec<Value> {
    let mut aces_list = Vec::new();

    // 1. Parse SD
    let (_, sd) = match SecurityDescriptor::parse(nt_blob) {
        Ok(res) => res,
        Err(_) => return aces_list,
    };

    // 2. Parse DACL if present
    if sd.offset_dacl > 0 && ((sd.offset_dacl as usize) < nt_blob.len()) {
        if let Ok((_, dacl)) = Acl::parse(&nt_blob[sd.offset_dacl as usize..]) {
             for ace in dacl.data {
                 process_ace(&ace, domain, &mut aces_list);
             }
        }
    }
    
    // We could also parse Owner/Group here for "Owns" edges
    if sd.offset_owner > 0 && ((sd.offset_owner as usize) < nt_blob.len()) {
        if let Ok((_, owner)) = LdapSid::parse(&nt_blob[sd.offset_owner as usize..]) {
             let sid_str = sid_maker(&owner, domain);
             aces_list.push(json!({
                 "PrincipalSID": sid_str,
                 "RightName": "Owns",
                 "IsInherited": false,
                 "PrincipalType": "User" // Guessing, fixed later by refinement
             }));
        }
    }

    aces_list
}

fn process_ace(ace: &Ace, domain: &str, list: &mut Vec<Value>) {
    // Basic implementation focusing on ACCESS_ALLOWED_ACE_TYPE (0x00) and ACCESS_ALLOWED_OBJECT_ACE_TYPE (0x05)
    
    // Mask is at offset 0 of body
    let mask = get_ace_mask(&ace.raw_body);
    let is_inherited = (ace.ace_flags & 0x10) != 0; // INHERITED_ACE_FLAG

    // Extract SID. Variable position depending on type.
    // For Type 0x00: Mask(4) + Sid(Variable)
    // For Type 0x05: Mask(4) + Flags(4) + ObjectType(16 optional) + InheritedObjectType(16 optional) + Sid
    
    let sid_blob = if ace.ace_type == 0x00 {
        if ace.raw_body.len() > 4 {
            &ace.raw_body[4..]
        } else { return; }
    } else if ace.ace_type == 0x05 {
        // Complex parsing for ObjectAce (Simplification for now: finding SID at end)
        // Robust parser needs full ObjectAce structure.
        // For MVP, if we can't cleanly parse Type 5 without `nom` logic for optional fields, we might skip.
        return; 
    } else {
        return;
    };

    let sid_str = match LdapSid::parse(sid_blob) {
        Ok((_, s)) => sid_maker(&s, domain),
        Err(_) => return, // Failed to parse SID
    };

    // Map rights
    let mut right = String::new();
    if (mask & GENERIC_ALL) == GENERIC_ALL { right = "GenericAll".to_string(); }
    else if (mask & WRITE_DACL) == WRITE_DACL { right = "WriteDacl".to_string(); }
    else if (mask & WRITE_OWNER) == WRITE_OWNER { right = "WriteOwner".to_string(); }
    else if (mask & GENERIC_WRITE) == GENERIC_WRITE { right = "GenericWrite".to_string(); }

    if !right.is_empty() {
        list.push(json!({
            "PrincipalSID": sid_str,
            "RightName": right,
            "IsInherited": is_inherited,
            "PrincipalType": "User" // Placeholder
        }));
    }
}
