use super::AmlError;

use super::pkglength::parse_pkg_length;
use super::termlist::{parse_term_arg, parse_term_list};

pub fn parse_type1_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    parse_def_while(data)
}

fn parse_def_while(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0xA2 {
        return Err(AmlError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (predicate, predicate_len) = parse_term_arg(&data[1 + pkg_length_len..])?;
    let term_list = parse_term_list(&data[1 + pkg_length_len + predicate_len .. 1 + pkg_length])?;

    Ok((12, pkg_length + 1))
}
