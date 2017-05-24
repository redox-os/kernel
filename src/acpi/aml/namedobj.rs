use collections::vec::Vec;
use collections::string::String;

use super::AmlError;

use super::namestring::{parse_name_string, parse_name_seg};
use super::termlist::{parse_term_arg, parse_term_list};
use super::pkglength::parse_pkg_length;

pub fn parse_named_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_def_op_region(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_def_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_def_method(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    Err(AmlError::AmlParseError)
}

fn parse_def_op_region(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x5B && data[1] != 0x80 {
        return Err(AmlError::AmlParseError);
    }

    let (name, name_len) = parse_name_string(&data[2..])?;
    let region = match data[2 + name_len] {
        0x00 ... 0x09 | 0x80 ... 0xFF => data[2 + name_len],
        _ => return Err(AmlError::AmlParseError)
    };
    
    let (offset, offset_len) = parse_term_arg(&data[3 + name_len..])?;
    let (len, len_len) = parse_term_arg(&data[3 + name_len + offset_len..])?;

    Ok((32, 3 + name_len + offset_len + len_len))
}

fn parse_def_field(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x5B && data[1] != 0x81 {
        return Err(AmlError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = parse_name_string(&data[2 + pkg_length_len .. 2 + pkg_length])?;

    let field_flags = data[2 + pkg_length_len + name_len];
    let field_list = parse_field_list(&data[3 + pkg_length_len + name_len .. 2 + pkg_length])?;

    Ok((42, 2 + pkg_length))
}

fn parse_field_list(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    let mut terms: Vec<u8> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let (res, len) = parse_field_element(&data[current_offset..])?;
        terms.push(res);
        current_offset += len;
    }

    Ok(terms)
}

fn parse_field_element(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_named_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_reserved_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_access_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_extended_access_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    parse_connect_field(data)
}

fn parse_named_field(data: &[u8]) -> Result<(u8, usize), AmlError> {
    let name = match String::from_utf8(parse_name_seg(&data[0..4])?) {
        Ok(s) => s,
        Err(_) => return Err(AmlError::AmlParseError)
    };
    let (length, length_len) = parse_pkg_length(&data[4..])?;

    Ok((1, 4 + length_len))
}

fn parse_reserved_field(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_access_field(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_extended_access_field(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_connect_field(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_def_method(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x14 {
        return Err(AmlError::AmlParseError);
    }

    let (pkg_len, pkg_len_len) = parse_pkg_length(&data[1..])?;
    let (name, name_len) = parse_name_string(&data[1 + pkg_len_len..])?;
    let method_flags = data[1 + pkg_len_len + name_len];

    println!("Method {}", name);
    let term_list = parse_term_list(&data[2 + pkg_len_len + name_len .. 1 + pkg_len])?;

    Ok((7, pkg_len + 1))
}
