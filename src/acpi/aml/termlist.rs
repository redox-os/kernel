use collections::vec::Vec;

use super::AmlError;
use super::namespacemodifier::parse_namespace_modifier;
use super::namedobj::parse_named_obj;

pub fn parse_term_list(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    let mut terms: Vec<u8> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        println!("{} {}", data[current_offset], data[current_offset + 1]);
        
        let (res, len) = parse_term_obj(&data[current_offset..])?;
        terms.push(res);
        current_offset += len;
    }

    Ok(terms)
}

fn parse_term_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_namespace_modifier(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_named_obj(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_type1_opcode(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    parse_type2_opcode(data)
}

pub fn parse_term_arg(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_type1_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_type2_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}
