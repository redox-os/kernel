use collections::vec::Vec;

use super::AmlError;
use super::namespacemodifier::parse_namespace_modifier;

pub fn parse_term_list(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    let mut terms: Vec<u8> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        println!("{} {}", data[current_offset], data[current_offset + 1]);
        match parse_namespace_modifier(&data[current_offset..]) {
            Ok((namespace_modifier, length)) => {
                terms.push(namespace_modifier);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => ()
        }

        match parse_named_obj(&data[current_offset..]) {
            Ok((named_obj, length)) => {
                terms.push(named_obj);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => ()
        }

        match parse_type1_opcode(&data[current_offset..]) {
            Ok((type1_opcode, length)) => {
                terms.push(type1_opcode);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => ()
        }

        match parse_type2_opcode(&data[current_offset..]) {
            Ok((type2_opcode, length)) => {
                terms.push(type2_opcode);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => return Ok(terms) //return Err(AmlError::AmlParseError)
        }
    }

    Ok(terms)
}

fn parse_named_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_type1_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_type2_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}
