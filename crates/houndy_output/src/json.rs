use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct BloodHoundJson {
    pub data: Vec<Node>,
    pub meta: Meta,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Meta {
    pub methods: u32,
    pub type_: String,
    pub count: u32,
    pub version: u32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")] // User, Computer, Group
pub enum Node {
    User(UserNode),
    Computer(ComputerNode),
    Group(GroupNode),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserNode {
    pub Properties: UserProperties,
    pub Aces: Vec<Ace>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ComputerNode {
    pub Properties: ComputerProperties,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupNode {
    pub Properties: GroupProperties,
    pub Members: Vec<MemberReference>,
}

// Placeholder structs for properties
#[derive(Serialize, Deserialize, Debug)]
pub struct UserProperties {
    pub name: String,
    pub domain: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ComputerProperties {
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupProperties {
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ace {
    pub PrincipalSID: String,
    pub RightName: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MemberReference {
    pub MemberId: String,
    pub MemberType: String,
}
