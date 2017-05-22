use collections::vec::Vec;

use super::sdt::Sdt;

pub enum AmlError {
    AmlParseError
}

pub struct AmlTables;

pub enum AmlValue {
    NothingToSeeHere,
    MoveAlongCitizen
}

pub fn parse_aml_table(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    parse_term_list(data)
}

fn parse_term_list(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    let mut terms: Vec<u8> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        match parse_namespace_modifier(data) {
            Ok((namespace_modifier, length)) => {
                terms.push(namespace_modifier);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => ()
        }

        match parse_named_obj(data) {
            Ok((named_obj, length)) => {
                terms.push(named_obj);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => ()
        }

        match parse_type1_opcode(data) {
            Ok((type1_opcode, length)) => {
                terms.push(type1_opcode);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => ()
        }

        match parse_type2_opcode(data) {
            Ok((type2_opcode, length)) => {
                terms.push(type2_opcode);
                current_offset += length;
                continue;
            },
            Err(AmlError::AmlParseError) => break //return Err(AmlError::AmlParseError)
        }
    }

    Ok(terms)
}

fn parse_namespace_modifier(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
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
