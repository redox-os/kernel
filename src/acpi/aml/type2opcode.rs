use super::AmlError;

use super::termlist::parse_term_arg;
use super::namestring::parse_super_name;

pub fn parse_type2_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_def_lless(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    match parse_def_size_of(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_def_store(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }

    match parse_def_subtract(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    match parse_def_to_buffer(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    match parse_def_to_hex_string(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    Err(AmlError::AmlParseError)
}

fn parse_def_lless(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x95 {
        return Err(AmlError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((12, 1 + lhs_len + rhs_len))
}

fn parse_def_to_hex_string(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x98 {
        return Err(AmlError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_super_name(&data[1 + operand_len..])?;

    Ok((8, 1 + operand_len + target_len))
}

fn parse_def_to_buffer(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x96 {
        return Err(AmlError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_super_name(&data[1 + operand_len..])?;

    Ok((8, 1 + operand_len + target_len))
}

fn parse_def_subtract(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x74 {
        return Err(AmlError::AmlParseError);
    }

    let (minuend, minuend_len) = parse_term_arg(&data[1..])?;
    let (subtrahend, subtrahend_len) = parse_term_arg(&data[1 + minuend_len..])?;
    let (target, target_len) = parse_super_name(&data[1 + minuend_len + subtrahend_len..])?;

    Ok((8, 1 + minuend_len + subtrahend_len + target_len))
}

fn parse_def_size_of(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x87 {
        return Err(AmlError::AmlParseError);
    }

    let (name, name_len) = parse_super_name(&data[1..])?;
    Ok((name, name_len + 1))
}

fn parse_def_store(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x70 {
        return Err(AmlError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_super_name(&data[1 + operand_len..])?;

    Ok((target, operand_len + target_len + 1))
}
