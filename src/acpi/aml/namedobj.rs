use super::AmlError;

use super::namestring::parse_name_string;

pub fn parse_named_obj(data: &[u8]) -> Result<(u8, usize), AmlError> {
    match parse_def_op_region(data) {
        Ok((result, length)) => Ok((result, length)),
        Err(AmlError::AmlParseError) => Err(AmlError::AmlParseError)
    }
}

fn parse_def_op_region(data: &[u8]) -> Result<(u8, usize), AmlError> {
    if data[0] != 0x5B && data[1] != 0x80 {
        // ExtOpPrefix, OpRegionOp
        return Err(AmlError::AmlParseError);
    }

    let (name, name_len) = parse_name_string(&data[2..])?;
    let region = match data[2 + name_len] {
        0x00 ... 0x09 | 0x80 ... 0xFF => data[2 + name_len],
        _ => return Err(AmlError::AmlParseError)
    };
    
    let offset = data[3 + name_len];
    let len = data[4 + name_len];

    println!("Operation Region Found: {}\n\tSpace: {}\n\tOffset: {}\n\tLength:{}\n",
             name, region, offset, len);

    Ok((32, 5 + name_len))
}
