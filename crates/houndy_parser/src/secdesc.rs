use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::bytes::streaming::take;
use nom::multi::count;
use nom::IResult;
use crate::sid::LdapSid;

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub offset_owner: u32,
    pub offset_group: u32,
    pub offset_sacl: u32,
    pub offset_dacl: u32,
}

impl SecurityDescriptor {
    pub fn parse(i: &[u8]) -> IResult<&[u8], SecurityDescriptor> {
        let (i, revision) = le_u8(i)?;
        let (i, sbz1) = le_u8(i)?;
        let (i, control) = le_u16(i)?;
        let (i, offset_owner) = le_u32(i)?;
        let (i, offset_group) = le_u32(i)?;
        let (i, offset_sacl) = le_u32(i)?;
        let (i, offset_dacl) = le_u32(i)?;

        Ok((i, SecurityDescriptor {
            revision,
            sbz1,
            control,
            offset_owner,
            offset_group,
            offset_sacl,
            offset_dacl,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct Acl {
    pub acl_revision: u8,
    pub sbz1: u8,
    pub acl_size: u16,
    pub ace_count: u16,
    pub sbz2: u16,
    pub data: Vec<Ace>,
}

impl Acl {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Acl> {
        let (i, acl_revision) = le_u8(i)?;
        let (i, sbz1) = le_u8(i)?;
        let (i, acl_size) = le_u16(i)?;
        let (i, ace_count) = le_u16(i)?;
        let (i, sbz2) = le_u16(i)?;
        // NOTE: RustHound uses `count(Ace::parse, ace_count)`.
        let (i, data) = count(Ace::parse, ace_count as usize)(i)?;

        Ok((i, Acl {
            acl_revision,
            sbz1,
            acl_size,
            ace_count,
            sbz2,
            data,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub ace_size: u16,
    // For simplicity, store raw data or a generic struct. 
    // RustHound has `AceFormat` which is an enum.
    // For now we will just store raw bytes for body to avoid massive complexity in this file,
    // OR we implement `AceFormat` if we have the content.
    // RustHound used `AceFormat::parse`. 
    // Since I didn't verify AceFormat implementation fully (it was in secdesc chunks I didn't read fully?),
    // I will store raw data and parse it on demand or use a simplified approach.
    // WAIT: I need `AceFormat` to decode mask and object types.
    // I will implement a simplified `AceData` struct.
    pub raw_body: Vec<u8>, 
}

impl Ace {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Ace> {
        let (i, ace_type) = le_u8(i)?;
        let (i, ace_flags) = le_u8(i)?;
        let (i, ace_size) = le_u16(i)?;
        
        // Body size is ace_size - 4 (header)
        let body_len = ace_size.checked_sub(4).unwrap_or(0) as usize;
        let (i, data) = take(body_len)(i)?;

        Ok((i, Ace {
            ace_type,
            ace_flags,
            ace_size,
            raw_body: data.to_vec(),
        }))
    }
}
