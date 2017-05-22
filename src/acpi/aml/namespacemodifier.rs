use collections::vec::Vec;

use super::AmlError;
use super::pkglength::parse_pkg_length;
use super::namestring::parse_name_string;
use super::termlist::parse_term_list;

pub fn parse_namespace_modifier(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x10 {
        return Err(AmlError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = match parse_pkg_length(&data[1..]) {
        Ok((l, o)) => (l, o),
        Err(AmlError::AmlParseError) => return Err(AmlError::AmlParseError)
    };

    let (name, name_len) = match parse_name_string(&data[1 + pkg_length_len..]) {
        Ok((n, o)) => (n, o),
        Err(AmlError::AmlParseError) => return Err(AmlError::AmlParseError)
    };

    let remaining = pkg_length - (pkg_length_len + name_len);
    // Number of bytes in the term list

    let terms = match parse_term_list(&data[1 + pkg_length_len + name_len..]) {
        Ok(t) => t,
        Err(AmlError::AmlParseError) => return Err(AmlError::AmlParseError)
    };

    Ok((12, pkg_length + 1))
}
