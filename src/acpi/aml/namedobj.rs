use collections::vec::Vec;
use collections::string::String;

use super::AmlInternalError;

use super::namestring::{parse_name_string, parse_name_seg};
use super::termlist::{parse_term_arg, parse_term_list, parse_object_list, TermArg, TermObj, Object};
use super::pkglength::parse_pkg_length;
use super::type2opcode::{parse_def_buffer, DefBuffer};

#[derive(Debug)]
pub enum NamedObj {
    DefBankField {
        region_name: String,
        bank_name: String,
        bank_value: TermArg,
        flags: FieldFlags,
        field_list: Vec<FieldElement>
    },
    DefCreateDWordField {
        name: String,
        source_buf: TermArg,
        byte_index: TermArg
    },
    DefDevice {
        name: String,
        obj_list: Vec<Object>
    },
    DefOpRegion {
        name: String,
        region: RegionSpace,
        offset: TermArg,
        len: TermArg
    },
    DefField {
        name: String,
        flags: FieldFlags,
        field_list: Vec<FieldElement>
    },
    DefMethod {
        name: String,
        arg_count: u8,
        serialized: bool,
        sync_level: u8,
        term_list: Vec<TermObj>
    },
    DefMutex {
        name: String,
        sync_level: u8
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug)]
pub enum RegionSpace {
    SystemMemory,
    SystemIO,
    PCIConfig,
    EmbeddedControl,
    SMBus,
    SystemCMOS,
    PciBarTarget,
    IPMI,
    GeneralPurposeIO,
    GenericSerialBus,
    UserDefined(u8)
}

#[derive(Debug)]
pub struct FieldFlags {
    access_type: AccessType,
    lock_rule: bool,
    update_rule: UpdateRule
}

#[derive(Debug)]
pub enum AccessType {
    AnyAcc,
    ByteAcc,
    WordAcc,
    DWordAcc,
    QWordAcc,
    BufferAcc
}

#[derive(Debug)]
pub enum UpdateRule {
    Preserve,
    WriteAsOnes,
    WriteAsZeros
}

#[derive(Debug)]
pub enum FieldElement {
    NamedField {
        name: String,
        length: usize
    },
    ReservedField {
        length: usize
    },
    AccessField {
        access_type: AccessType,
        access_attrib: AccessAttrib
    },
    ConnectFieldNameString(String),
    ConnectFieldBufferData(DefBuffer)
}

#[derive(Debug)]
pub enum AccessAttrib {
    AttribBytes(u8),
    AttribRawBytes(u8),
    AttribRawProcessBytes(u8),
    AttribQuick,
    AttribSendReceive,
    AttribByte,
    AttribWord,
    AttribBlock,
    AttribProcessCall,
    AttribBlockProcessCall
}

pub fn parse_named_obj(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    match parse_def_bank_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_create_dword_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_device(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_op_region(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_method(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_mutex(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    Err(AmlInternalError::AmlParseError)
}

fn parse_def_bank_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x87 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (region_name, region_name_len) = match parse_name_string(
            &data[2 + pkg_length_len .. 2 + pkg_length]) {
        Ok(res) => res,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Ok((NamedObj::DeferredLoad(
            data[0 .. 2 + pkg_length].to_vec()
        ), 2 + pkg_length))
    };

    let (bank_name, bank_name_len) = match parse_name_string(
            &data[2 + pkg_length_len + region_name_len .. 2 + pkg_length]) {
        Ok(res) => res,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Ok((NamedObj::DeferredLoad(
            data[0 .. 2 + pkg_length].to_vec()
        ), 2 + pkg_length))
    };

    let (bank_value, bank_value_len) = match parse_term_arg(
            &data[2 + pkg_length_len + region_name_len .. 2 + pkg_length]) {
        Ok(res) => res,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Ok((NamedObj::DeferredLoad(
            data[0 .. 2 + pkg_length].to_vec()
        ), 2 + pkg_length))
    };

    let flags_raw = data[2 + pkg_length_len + region_name_len + bank_name_len + bank_value_len];
    let flags = FieldFlags {
        access_type: match flags_raw & 0x0F {
            0 => AccessType::AnyAcc,
            1 => AccessType::ByteAcc,
            2 => AccessType::WordAcc,
            3 => AccessType::DWordAcc,
            4 => AccessType::QWordAcc,
            5 => AccessType::BufferAcc,
            _ => return Err(AmlInternalError::AmlParseError)
        },
        lock_rule: (flags_raw & 0x10) == 0x10,
        update_rule: match (flags_raw & 0x60) >> 5 {
            0 => UpdateRule::Preserve,
            1 => UpdateRule::WriteAsOnes,
            2 => UpdateRule::WriteAsZeros,
            _ => return Err(AmlInternalError::AmlParseError)
        }
    };
    
    let field_list = match parse_field_list(
        &data[3 + pkg_length_len + region_name_len + bank_name_len + bank_value_len ..
              2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 2 + pkg_length))
    };
    
    Ok((NamedObj::DefBankField {region_name, bank_name, bank_value, flags, field_list},
        2 + pkg_length))
}

fn parse_def_create_dword_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x8A {
        return Err(AmlInternalError::AmlParseError);
    }

    let (source_buf, source_buf_len) = parse_term_arg(&data[1..])?;
    let (byte_index, byte_index_len) = parse_term_arg(&data[1 + source_buf_len..])?;
    let (name, name_len) = parse_name_string(&data[1 + source_buf_len + byte_index_len..])?;

    Ok((NamedObj::DefCreateDWordField {name, source_buf, byte_index},
        1 + source_buf_len + byte_index_len + name_len))
}


fn parse_def_device(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x82 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_length_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 2 + pkg_length))
    };

    let obj_list = match parse_object_list(&data[2 + pkg_length_len + name_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 2 + pkg_length))
    };

    Ok((NamedObj::DefDevice {name, obj_list}, 2 + pkg_length_len))
}

fn parse_def_op_region(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x80 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (name, name_len) = parse_name_string(&data[2..])?;
    let region = match data[2 + name_len] {
        0x00 => RegionSpace::SystemMemory,
        0x01 => RegionSpace::SystemIO,
        0x02 => RegionSpace::PCIConfig,
        0x03 => RegionSpace::EmbeddedControl,
        0x04 => RegionSpace::SMBus,
        0x05 => RegionSpace::SystemCMOS,
        0x06 => RegionSpace::PciBarTarget,
        0x07 => RegionSpace::IPMI,
        0x08 => RegionSpace::GeneralPurposeIO,
        0x09 => RegionSpace::GenericSerialBus,
        0x80 ... 0xFF => RegionSpace::UserDefined(data[2 + name_len]),
        _ => return Err(AmlInternalError::AmlParseError)
    };
    
    let (offset, offset_len) = parse_term_arg(&data[3 + name_len..])?;
    let (len, len_len) = parse_term_arg(&data[3 + name_len + offset_len..])?;

    Ok((NamedObj::DefOpRegion {name, region, offset, len}, 3 + name_len + offset_len + len_len))
}

fn parse_def_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x81 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_length_len .. 2 + pkg_length])  {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 2 + pkg_length))
    };

    let flags_raw = data[2 + pkg_length_len + name_len];
    let flags = FieldFlags {
        access_type: match flags_raw & 0x0F {
            0 => AccessType::AnyAcc,
            1 => AccessType::ByteAcc,
            2 => AccessType::WordAcc,
            3 => AccessType::DWordAcc,
            4 => AccessType::QWordAcc,
            5 => AccessType::BufferAcc,
            _ => return Err(AmlInternalError::AmlParseError)
        },
        lock_rule: (flags_raw & 0x10) == 0x10,
        update_rule: match (flags_raw & 0x60) >> 5 {
            0 => UpdateRule::Preserve,
            1 => UpdateRule::WriteAsOnes,
            2 => UpdateRule::WriteAsZeros,
            _ => return Err(AmlInternalError::AmlParseError)
        }
    };
    
    let field_list = match parse_field_list(&data[3 + pkg_length_len + name_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 2 + pkg_length))
    };

    Ok((NamedObj::DefField {name, flags, field_list}, 2 + pkg_length))
}

fn parse_field_list(data: &[u8]) -> Result<Vec<FieldElement>, AmlInternalError> {
    let mut terms: Vec<FieldElement> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let (res, len) = parse_field_element(&data[current_offset..])?;
        terms.push(res);
        current_offset += len;
    }

    Ok(terms)
}

fn parse_field_element(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    match parse_named_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_reserved_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_access_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_extended_access_field(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    parse_connect_field(data)
}

fn parse_named_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    let name = match String::from_utf8(parse_name_seg(&data[0..4])?) {
        Ok(s) => s,
        Err(_) => return Err(AmlInternalError::AmlParseError)
    };
    let (length, length_len) = parse_pkg_length(&data[4..])?;

    Ok((FieldElement::NamedField {name, length}, 4 + length_len))
}

fn parse_reserved_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    if data[0] != 0x00 {
        return Err(AmlInternalError::AmlParseError);
    }
    
    let (length, length_len) = parse_pkg_length(&data[1..])?;
    Ok((FieldElement::ReservedField {length}, 1 + length_len))
}

fn parse_access_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    if data[0] != 0x01 {
        return Err(AmlInternalError::AmlParseError);
    }
    
    let flags_raw = data[1];
    let access_type = match flags_raw & 0x0F {
        0 => AccessType::AnyAcc,
        1 => AccessType::ByteAcc,
        2 => AccessType::WordAcc,
        3 => AccessType::DWordAcc,
        4 => AccessType::QWordAcc,
        5 => AccessType::BufferAcc,
        _ => return Err(AmlInternalError::AmlParseError)
    };

    let access_attrib = match (flags_raw & 0xC0) >> 6 {
        0 => match data[2] {
            0x02 => AccessAttrib::AttribQuick,
            0x04 => AccessAttrib::AttribSendReceive,
            0x06 => AccessAttrib::AttribByte,
            0x08 => AccessAttrib::AttribWord,
            0x0A => AccessAttrib::AttribBlock,
            0x0C => AccessAttrib::AttribProcessCall,
            0x0D => AccessAttrib::AttribBlockProcessCall,
            _ => return Err(AmlInternalError::AmlParseError)
        },
        1 => AccessAttrib::AttribBytes(data[2]),
        2 => AccessAttrib::AttribRawBytes(data[2]),
        3 => AccessAttrib::AttribRawProcessBytes(data[2]),
        _ => return Err(AmlInternalError::AmlParseError)
            // This should never happen but the compiler bitches if I don't cover this
    };

    return Ok((FieldElement::AccessField {access_type, access_attrib}, 3 as usize))
}

fn parse_extended_access_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    Err(AmlInternalError::AmlParseError)
}

fn parse_connect_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    if data[0] != 0x02 {
        return Err(AmlInternalError::AmlParseError);
    }

    match parse_def_buffer(&data[1..]) {
        Ok((buf, buf_len)) => return Ok((FieldElement::ConnectFieldBufferData(buf), buf_len + 1)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_name_string(&data[1..]) {
        Ok((name, name_len)) => Ok((FieldElement::ConnectFieldNameString(name), name_len + 1)),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }    
}

fn parse_def_method(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x14 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_len, pkg_len_len) = parse_pkg_length(&data[1..])?;
    let (name, name_len) = match parse_name_string(&data[1 + pkg_len_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_len].to_vec()), 1 + pkg_len))
    };
    let flags = data[1 + pkg_len_len + name_len];

    let arg_count = flags & 0x07;
    let serialized = (flags & 0x08) == 0x08;
    let sync_level = flags & 0xF0 >> 4;

    let term_list = match parse_term_list(&data[2 + pkg_len_len + name_len .. 1 + pkg_len]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_len].to_vec()), 1 + pkg_len))
    };

    Ok((NamedObj::DefMethod {name, arg_count, serialized, sync_level, term_list}, pkg_len + 1))
}

fn parse_def_mutex(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x01 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (name, name_len) = match parse_name_string(&data[2 ..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    };
    let flags = data[2 + name_len];
    let sync_level = flags & 0x0F;

    Ok((NamedObj::DefMutex {name, sync_level}, name_len + 3))
}
