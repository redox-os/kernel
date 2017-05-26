use collections::vec::Vec;

use super::AmlError;
use super::namespacemodifier::parse_namespace_modifier;
use super::namedobj::parse_named_obj;
use super::dataobj::{parse_data_obj, parse_arg_obj, parse_local_obj};
use super::type1opcode::parse_type1_opcode;
use super::type2opcode::parse_type2_opcode;

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

pub fn parse_term_arg(data: &[u8]) -> Result<(u8, usize), AmlError> {
    println!("{}", data[0]);
    match parse_type2_opcode(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_data_obj(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    match parse_arg_obj(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    parse_local_obj(data)
}

pub fn parse_object_list(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    let mut terms: Vec<u8> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        println!("{} {}", data[current_offset], data[current_offset + 1]);
        
        let (res, len) = parse_object(&data[current_offset..])?;
        terms.push(res);
        current_offset += len;
    }

    Ok(terms)
}

fn parse_object(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_namespace_modifier(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    parse_named_obj(data)
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
