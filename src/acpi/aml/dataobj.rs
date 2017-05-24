use super::AmlError;

pub fn parse_data_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_computational_data(data) {
        Ok(res) => return Ok(res),
        Err(AmlError::AmlParseError) => ()
    }
    
    Err(AmlError::AmlParseError)
        // Rest currently isn't implemented
}

pub fn parse_arg_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

pub fn parse_local_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    Err(AmlError::AmlParseError)
}

fn parse_computational_data(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match data[0] {
        0x0A => Ok((5, 2 as usize)), // Byte
        0x0B => Ok((6, 3 as usize)), // Word
        0x0C => Ok((7, 5 as usize)), // DWord
        0x0E => Ok((8, 9 as usize)), // QWord
        0x00 => Ok((0, 1 as usize)), // Zero
        0x01 => Ok((1, 1 as usize)), // One
        0xFF => Ok((2, 1 as usize)), // Ones
        _ => Err(AmlError::AmlParseError)
    }
}
