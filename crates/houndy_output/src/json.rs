use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BloodHoundJson {
    // BloodHound expects "data" to be the array of nodes
    pub data: Vec<Node>,
    pub meta: Meta,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Meta {
    pub methods: u32,
    pub type_: String,
    pub count: u32,
    pub version: u32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "type")] // User, Computer, Group
pub enum Node {
    User(UserNode),
    Computer(ComputerNode),
    Group(GroupNode),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct UserNode {
    pub properties: UserProperties,
    pub aces: Vec<Ace>,
    // Add other lists like ObjectIdentifier, IsDeleted if needed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_identifier: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerNode {
    pub properties: ComputerProperties,
    pub aces: Vec<Ace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_identifier: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GroupNode {
    pub properties: GroupProperties,
    pub members: Vec<MemberReference>,
    pub aces: Vec<Ace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_identifier: Option<String>,
}

// Placeholder structs for properties
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct UserProperties {
    pub domain: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distinguished_name: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    // Add other BH properties: Email, DisplayName, etc.
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerProperties {
    pub domain: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distinguished_name: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GroupProperties {
    pub domain: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distinguished_name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Ace {
    pub principal_s_i_d: String,
    pub right_name: String,
    pub is_inherited: bool,
    pub principal_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct MemberReference {
    pub member_id: String,
    pub member_type: String,
}
