use collections::vec::Vec;

use super::AmlError;
use super::pkglength::parse_pkg_length;
use super::namestring::parse_name_string;
use super::termlist::parse_term_list;

pub fn parse_namespace_modifier(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_scope_op(data) {
        Ok(res) => Ok(res),
        Err(AmlError::AmlParseError) => Err(AmlError::AmlParseError)
    }
}

fn parse_scope_op(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x10 {
        return Err(AmlError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (name, name_len) = parse_name_string(&data[1 + pkg_length_len..])?;
    
    println!("{} {{", name);
    
    let terms = parse_term_list(&data[1 + pkg_length_len + name_len..])?;

    println!("}}");
    
    Ok((12, pkg_length + 1))
}
