use super::AmlError;

use super::termlist::parse_term_arg;

pub fn parse_type2_opcode(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_def_to_hex_string(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    Err(AmlError::AmlParseError)
}

fn parse_def_to_hex_string(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x98 {
        return Err(AmlError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_term_arg(&data[1 + operand_len..])?;

    Ok((8, 1 + operand_len + target_len))
}
