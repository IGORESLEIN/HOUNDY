use houndy_output::json::{
    Node, UserNode, ComputerNode, GroupNode, 
    UserProperties, ComputerProperties, GroupProperties, 
    Ace, MemberReference
};
use houndy_protocol::SearchEntry;
use houndy_parser::sid::objectsid_to_string;
use houndy_parser::acl::parse_ntsecuritydescriptor;
use serde_json::Value;

pub fn convert_users(entries: Vec<SearchEntry>, domain: &str) -> Vec<Node> {
    let mut nodes = Vec::new();

    for entry in entries {
        let attrs = &entry.attrs;

        // Extract critical attributes
        let name = get_str(attrs, "sAMAccountName");
        let dist_name = get_str(attrs, "distinguishedName");
        
        let sid_bytes = get_bin_entry(&entry, "objectSid");
        let sid = objectsid_to_string(&sid_bytes);
        
        // ACLs
        let nt_sec_desc = get_bin_entry(&entry, "nTSecurityDescriptor");
        let aces = if !nt_sec_desc.is_empty() {
            let user_domain_sid = sid.rsplitn(2, '-').last().unwrap_or("").to_string(); // Rough domain SID guess? Or pass it?
            // Actually domain param is DNS name. We need Domain SID for some checks but parser needs domain name?
            // parse_ntsecuritydescriptor takes domain string to resolve SIDs if needed? 
            // It actually uses it to format SIDs if Short.
            convert_json_aces(parse_ntsecuritydescriptor(&nt_sec_desc, domain))
        } else {
            vec![]
        };

        let uac = get_u32(attrs, "userAccountControl");
        let enabled = (uac & 2) == 0; // ACCOUNTDISABLE = 0x0002

        // Construct Name (USER@DOMAIN)
        let bh_name = format!("{}@{}", name.to_uppercase(), domain.to_uppercase());

        let props = UserProperties {
            name: bh_name.clone(),
            domain: domain.to_uppercase(),
            distinguished_name: Some(dist_name),
            enabled,
            description: Some(get_str(attrs, "description")),
        };

        let node = UserNode {
            properties: props,
            aces,
            object_identifier: Some(sid),
        };

        nodes.push(Node::User(node));
    }

    nodes
}

pub fn convert_computers(entries: Vec<SearchEntry>, domain: &str) -> Vec<Node> {
    let mut nodes = Vec::new();

    for entry in entries {
        let attrs = &entry.attrs;

        let name = get_str(attrs, "dNSHostName"); // Prefer DNS name
        let sam = get_str(attrs, "sAMAccountName");
        // Fallback if DNS is empty
        let final_name = if name.is_empty() { 
             // Remove $ from sAMAccountName if present
             sam.trim_end_matches('$').to_string()
        } else {
             name
        };

        let dist_name = get_str(attrs, "distinguishedName");
        let sid_bytes = get_bin_entry(&entry, "objectSid");
        let sid = objectsid_to_string(&sid_bytes);
        
        // ACLs
        let nt_sec_desc = get_bin_entry(&entry, "nTSecurityDescriptor");
        let aces = if !nt_sec_desc.is_empty() {
            convert_json_aces(parse_ntsecuritydescriptor(&nt_sec_desc, domain))
        } else {
            vec![]
        };

        let uac = get_u32(attrs, "userAccountControl");
        let enabled = (uac & 2) == 0;
        let os = get_str(attrs, "operatingSystem");

        let bh_name = format!("{}.{}", final_name.to_uppercase(), domain.to_uppercase());

        let props = ComputerProperties {
            name: bh_name,
            domain: domain.to_uppercase(),
            distinguished_name: Some(dist_name),
            enabled,
            operating_system: Some(os),
        };

        let node = ComputerNode {
            properties: props,
            aces,
            object_identifier: Some(sid),
        };

        nodes.push(Node::Computer(node));
    }
    nodes
}

use std::collections::HashMap;

pub fn convert_groups(entries: Vec<SearchEntry>, domain: &str, sid_map: &HashMap<String, String>) -> Vec<Node> {
    let mut nodes = Vec::new();

    for entry in entries {
        let attrs = &entry.attrs;
        let name = get_str(attrs, "sAMAccountName");
        let dist_name = get_str(attrs, "distinguishedName");
        let sid_bytes = get_bin_entry(&entry, "objectSid");
        let sid = objectsid_to_string(&sid_bytes);

        // ACLs
        let nt_sec_desc = get_bin_entry(&entry, "nTSecurityDescriptor");
        let aces = if !nt_sec_desc.is_empty() {
            convert_json_aces(parse_ntsecuritydescriptor(&nt_sec_desc, domain))
        } else {
            vec![]
        };

        let bh_name = format!("{}@{}", name.to_uppercase(), domain.to_uppercase());

        let props = GroupProperties {
            name: bh_name,
            domain: domain.to_uppercase(),
            distinguished_name: Some(dist_name),
        };

        let mut members = Vec::new();
        for member_dn in attrs.get("member").unwrap_or(&vec![]) {
             if let Some(member_sid) = sid_map.get(&member_dn.to_uppercase()) {
                 members.push(MemberReference {
                     member_id: member_sid.clone(),
                     member_type: "User".to_string(), // Defaulting to User, could be Computer/Group. 
                     // Ideally we track type in the map too, but SID is what matters most.
                 });
             }
        }

        let node = GroupNode {
            properties: props,
            members,
            aces,
            object_identifier: Some(sid),
        };

        nodes.push(Node::Group(node));
    }
    nodes
}

// Helpers
pub fn get_str(attrs: &std::collections::HashMap<String, Vec<String>>, key: &str) -> String {
    if let Some(vals) = attrs.get(key) {
        if !vals.is_empty() {
            return vals[0].clone();
        }
    }
    String::new()
}

fn get_u32(attrs: &std::collections::HashMap<String, Vec<String>>, key: &str) -> u32 {
    let s = get_str(attrs, key);
    s.parse::<u32>().unwrap_or(0)
}

pub fn get_bin_entry(entry: &SearchEntry, key: &str) -> Vec<u8> {
    if let Some(vals) = entry.bin_attrs.get(key) {
        if !vals.is_empty() {
            return vals[0].clone();
        }
    }
    Vec::new()
}

fn convert_json_aces(json_aces: Vec<Value>) -> Vec<Ace> {
    let mut aces = Vec::new();
    for j in json_aces {
        let sid = j["PrincipalSID"].as_str().unwrap_or("").to_string();
        let right = j["RightName"].as_str().unwrap_or("").to_string();
        let inherited = j["IsInherited"].as_bool().unwrap_or(false);
        let ptype = j["PrincipalType"].as_str().unwrap_or("User").to_string();

        if !sid.is_empty() && !right.is_empty() {
            aces.push(Ace {
                principal_s_i_d: sid,
                right_name: right,
                is_inherited: inherited,
                principal_type: ptype,
            });
        }
    }
    aces
}
