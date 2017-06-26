use collections::vec::Vec;
use collections::string::String;

use super::AmlInternalError;

use super::dataobj::{parse_arg_obj, parse_local_obj, ArgObj, LocalObj};
use super::type2opcode::{parse_type6_opcode, Type6OpCode};

#[derive(Debug, Clone)]
pub enum SuperName {
    NameString(String),
    ArgObj(ArgObj),
    LocalObj(LocalObj),
    DebugObj,
    Type6OpCode(Type6OpCode)
}

#[derive(Debug, Clone)]
pub enum Target {
    SuperName(SuperName),
    Null
}

pub fn parse_name_string(data: &[u8]) -> Result<(String, usize), AmlInternalError> {
    let mut characters: Vec<u8> = vec!();
    let mut starting_index: usize = 0;

    if data[0] == 0x5C {
        characters.push(data[0]);
        starting_index = 1;
    } else if data[0] == 0x5E {
        while data[starting_index] == 0x5E {
            characters.push(data[starting_index]);
            starting_index += 1;
        }
    }

    let sel = |data| {
        parser_selector! {
            data,
            parse_dual_name_path,
            parse_multi_name_path,
            parse_null_name,
            parse_name_seg
        };

        Err(AmlInternalError::AmlInvalidOpCode)
    };
    let (mut chr, len) = sel(&data[starting_index..])?;
    characters.append(&mut chr);

    let name_string = String::from_utf8(characters);

    match name_string {
        Ok(s) => Ok((s.clone(), len + starting_index)),
        Err(_) => Err(AmlInternalError::AmlParseError("Namestring - Name is invalid"))
    }
}

fn parse_null_name(data: &[u8]) -> Result<(Vec<u8>, usize), AmlInternalError> {
    parser_opcode!(data, 0x00);
    Ok((vec!(), 1 as usize))
}

pub fn parse_name_seg(data: &[u8]) -> Result<(Vec<u8>, usize), AmlInternalError> {
    match data[0] {
        0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlInvalidOpCode)
    }

    match data[1] {
        0x30 ... 0x39 | 0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlInvalidOpCode)
    }

    match data[2] {
        0x30 ... 0x39 | 0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlInvalidOpCode)
    }

    match data[3] {
        0x30 ... 0x39 | 0x41 ... 0x5A | 0x5F => (),
        _ => return Err(AmlInternalError::AmlInvalidOpCode)
    }

    let mut name_seg = vec!(data[0], data[1], data[2], data[3]);
    while *(name_seg.last().unwrap()) == 0x5F {
        name_seg.pop();
    }

    Ok((name_seg, 4 as usize))
}

fn parse_dual_name_path(data: &[u8]) -> Result<(Vec<u8>, usize), AmlInternalError> {
    parser_opcode!(data, 0x2E);

    let mut characters: Vec<u8> = vec!();
    let mut dual_len: usize = 1;

    match parse_name_seg(&data[1..5]) {
        Ok((mut v, len)) => {
            characters.append(&mut v);
            dual_len += len;
        },
        Err(e) => return Err(e)
    }

    characters.push(0x2E);

    match parse_name_seg(&data[5..9]) {
        Ok((mut v, len)) => {
            characters.append(&mut v);
            dual_len += len;
        },
        Err(e) => return Err(e)
    }

    Ok((characters, dual_len))
}

fn parse_multi_name_path(data: &[u8]) -> Result<(Vec<u8>, usize), AmlInternalError> {
    parser_opcode!(data, 0x2F);

    let seg_count = data[1];
    if seg_count == 0x00 {
        return Err(AmlInternalError::AmlParseError("MultiName Path - can't have zero name segments"));
    }

    let mut current_seg = 0;
    let mut characters: Vec<u8> = vec!();
    let mut multi_len: usize = 2;
    
    while current_seg < seg_count {
        match parse_name_seg(&data[(current_seg as usize * 4) + 2 ..]) {
            Ok((mut v, len)) => {
                characters.append(&mut v);
                multi_len += len;
            },
            Err(e) => return Err(e)
        }

        characters.push(0x2E);

        current_seg += 1;
    }

    characters.pop();

    Ok((characters, multi_len))
}

pub fn parse_super_name(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    parser_selector! {
        data,
        parse_simple_name,
        parser_wrap!(SuperName::Type6OpCode, parse_type6_opcode),
        parse_debug_obj
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

fn parse_debug_obj(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x31);
    Ok((SuperName::DebugObj, 2 as usize))
}

pub fn parse_simple_name(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    parser_selector! {
        data,
        parser_wrap!(SuperName::NameString, parse_name_string),
        parser_wrap!(SuperName::ArgObj, parse_arg_obj),
        parser_wrap!(SuperName::LocalObj, parse_local_obj)
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_target(data: &[u8]) -> Result<(Target, usize), AmlInternalError> {
    if data[0] == 0x00 {
        Ok((Target::Null, 1 as usize))
    } else {
        match parse_super_name(data) {
            Ok((name, name_len)) => Ok((Target::SuperName(name), name_len)),
            Err(e) => Err(e)
        }
    }
}
