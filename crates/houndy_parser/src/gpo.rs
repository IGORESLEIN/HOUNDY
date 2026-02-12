use ini::Ini;
use anyhow::Result;
use std::collections::HashMap;

pub struct GpoParser;

impl GpoParser {
    pub fn parse_gpt_tmpl(content: &str) -> Result<HashMap<String, Vec<String>>> {
        // Parses GptTmpl.inf looking for [Privilege Rights] or [Group Membership]
        let i = Ini::load_from_str(content).map_err(|e| anyhow::anyhow!(e))?;
        
        let mut restrictions = HashMap::new();
        
        if let Some(section) = i.section(Some("Group Membership")) {
            for (key, value) in section.iter() {
                // key is usually the group SID, value is member list (SIDs)
                let members: Vec<String> = value.split(',')
                    .map(|s| s.trim_matches('*').to_string())
                    .collect();
                restrictions.insert(key.to_string(), members);
            }
        }
        
        Ok(restrictions)
    }
}
