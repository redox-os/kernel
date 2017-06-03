use collections::vec::Vec;
use collections::string::String;

use super::AmlInternalError;

use super::dataobj::{parse_arg_obj, parse_local_obj, ArgObj, LocalObj};
use super::type2opcode::{parse_type6_opcode, Type6OpCode};

#[derive(Debug)]
pub enum SuperName {
    NameString(String),
    ArgObj(ArgObj),
    LocalObj(LocalObj),
    DebugObj,
    Type6OpCode(Type6OpCode)
}

#[derive(Debug)]
pub enum Target {
    SuperName(SuperName),
    Null
}

pub fn parse_name_string(data: &[u8]) -> Result<(String, usize), AmlInternalError> {
    let mut characters: Vec<u8> = vec!();
    let mut starting_index: usize = 0;

    let mut control_bytes: usize = 0;

    if data[0] == 0x5C {
        characters.push(data[0]);
        starting_index = 1;
    } else if data[0] == 0x5E {
        while data[starting_index] == 0x5E {
            characters.push(data[starting_index]);
            starting_index += 1;
        }
    }

    // TODO: Ew. Clean this shit up
    match parse_name_seg(&data[starting_index..]) {
        Ok(mut v) => characters.append(&mut v),
        Err(AmlInternalError::AmlParseError) => 
            match parse_dual_name_path(&data[starting_index..]) {
                Ok(mut v) => {
                    characters.append(&mut v);
                    control_bytes = 1;
                },
                Err(AmlInternalError::AmlParseError) => 
                    match parse_multi_name_path(&data[starting_index..]) {
                        Ok(mut v) => {
                            characters.append(&mut v);
                            control_bytes = 2;
                        },
                        Err(AmlInternalError::AmlParseError) => 
                            match data[starting_index] {
                                0x00 => control_bytes = 1,
                                _ => return Err(AmlInternalError::AmlParseError)
                            },
                        Err(AmlInternalError::AmlDeferredLoad) =>
                            return Err(AmlInternalError::AmlDeferredLoad)
                    },
                Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
            },
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    let name_string = String::from_utf8(characters);

    match name_string {
        Ok(s) => Ok((s.clone(), s.clone().len() + control_bytes)),
        Err(_) => Err(AmlInternalError::AmlParseError)
    }
}

pub fn parse_name_seg(data: &[u8]) -> Result<Vec<u8>, AmlInternalError> {
    match data[0] {
        0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlParseError)
    }

    match data[1] {
        0x30 ... 0x39 | 0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlParseError)
    }

    match data[2] {
        0x30 ... 0x39 | 0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlParseError)
    }

    match data[3] {
        0x30 ... 0x39 | 0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlParseError)
    }

    Ok(vec!(data[0], data[1], data[2], data[3]))
}

fn parse_dual_name_path(data: &[u8]) -> Result<Vec<u8>, AmlInternalError> {
    if data[0] != 0x2E {
        return Err(AmlInternalError::AmlParseError);
    }

    let mut characters: Vec<u8> = vec!();

    match parse_name_seg(&data[1..5]) {
        Ok(mut v) => characters.append(&mut v),
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_name_seg(&data[5..9]) {
        Ok(mut v) => characters.append(&mut v),
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    Ok(characters)
}

fn parse_multi_name_path(data: &[u8]) -> Result<Vec<u8>, AmlInternalError> {
    if data[0] != 0x2F {
        return Err(AmlInternalError::AmlParseError);
    }

    let seg_count = data[1];
    if seg_count == 0x00 {
        return Err(AmlInternalError::AmlParseError);
    }

    let mut current_seg = 0;
    let mut characters: Vec<u8> = vec!();
    
    while current_seg < seg_count {
        match parse_name_seg(&data[(current_seg as usize * 4) + 2 ..
                                   ((current_seg as usize + 1) * 4) + 2]) {
            Ok(mut v) => characters.append(&mut v),
            Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
            Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
        }

        current_seg += 1;
    }

    Ok(characters)
}

pub fn parse_super_name(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    match parse_simple_name(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_type6_opcode(data) {
        Ok((op, len)) => return Ok((SuperName::Type6OpCode(op), len)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    if data[0] == 0x5B && data[1] == 0x31 {
        Ok((SuperName::DebugObj, 2 as usize))
    } else {
        Err(AmlInternalError::AmlParseError)
    }
}

pub fn parse_simple_name(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    match parse_name_string(data) {
        Ok((name, name_len)) => return Ok((SuperName::NameString(name), name_len)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_arg_obj(data) {
        Ok((arg, arg_len)) => return Ok((SuperName::ArgObj(arg), arg_len)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_local_obj(data) {
        Ok((local, local_len)) => Ok((SuperName::LocalObj(local), local_len)),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }
}

pub fn parse_target(data: &[u8]) -> Result<(Target, usize), AmlInternalError> {
    if data[0] == 0x00 {
        Ok((Target::Null, 1 as usize))
    } else {
        match parse_super_name(data) {
            Ok((name, name_len)) => Ok((Target::SuperName(name), name_len)),
            Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
            Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
        }
    }
}
