use collections::vec::Vec;
use collections::string::String;
use collections::boxed::Box;

use super::AmlInternalError;

use super::pkglength::parse_pkg_length;
use super::termlist::{parse_term_arg, parse_method_invocation, TermArg, MethodInvocation};
use super::namestring::{parse_super_name, parse_target, parse_name_string, SuperName, Target};
use super::dataobj::{parse_data_ref_obj, DataRefObj};

#[derive(Debug)]
pub enum Type2OpCode {
    DefAcquire {
        object: SuperName,
        timeout: u16
    },
    DefBuffer(DefBuffer),
    DefPackage(DefPackage),
    DefVarPackage(DefVarPackage),
    DefDerefOf(TermArg),
    DefRefOf(SuperName),
    DefIncrement(SuperName),
    DefIndex(DefIndex),
    DefCondRefOf {
        operand: SuperName,
        target: Target
    },
    DefLEqual {
        lhs: TermArg,
        rhs: TermArg
    },
    DefLLess {
        lhs: TermArg,
        rhs: TermArg
    },
    DefSizeOf(SuperName),
    DefStore {
        operand: TermArg,
        target: SuperName
    },
    DefSubtract {
        minuend: TermArg,
        subtrahend: TermArg,
        target: Target
    },
    DefToBuffer {
        operand: TermArg,
        target: Target
    },
    DefToHexString {
        operand: TermArg,
        target: Target
    },
    DefConcat {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefConcatRes {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefAdd {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefAnd {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefOr {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    MethodInvocation(MethodInvocation),
    DeferredLoad(Vec<u8>)
}

#[derive(Debug)]
pub enum Type6OpCode {
    DefDerefOf(TermArg),
    DefRefOf(Box<SuperName>),
    DefIndex(DefIndex),
    MethodInvocation(MethodInvocation)
}

#[derive(Debug)]
pub struct DefIndex {
    obj: TermArg,
    idx: TermArg,
    target: Box<Target>
}

#[derive(Debug)]
pub enum DefBuffer {
    Buffer {
        buffer_size: TermArg,
        byte_list: Vec<u8>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug)]
pub enum DefPackage {
    Package {
        num_elements: u8,
        elements: Vec<PackageElement>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug)]
pub enum DefVarPackage {
    Package {
        num_elements: TermArg,
        elements: Vec<PackageElement>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug)]
pub enum PackageElement {
    DataRefObj(DataRefObj),
    NameString(String)
}

pub fn parse_type2_opcode(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    match parse_def_acquire(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_buffer(data) {
        Ok((res, size)) => return Ok((Type2OpCode::DefBuffer(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_package(data) {
        Ok((res, size)) => return Ok((Type2OpCode::DefPackage(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_var_package(data) {
        Ok((res, size)) => return Ok((Type2OpCode::DefVarPackage(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_deref_of(data) {
        Ok((res, size)) => return Ok((Type2OpCode::DefDerefOf(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_ref_of(data) {
        Ok((res, size)) => return Ok((Type2OpCode::DefRefOf(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_increment(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_index(data) {
        Ok((res, size)) => return Ok((Type2OpCode::DefIndex(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_lequal(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_lless(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_size_of(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_store(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_subtract(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_to_buffer(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_to_hex_string(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_add(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_and(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_or(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_concat_res(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_concat(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_cond_ref_of(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_method_invocation(data) {
        Ok((mi, size)) => Ok((Type2OpCode::MethodInvocation(mi), size)),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }
}

pub fn parse_type6_opcode(data: &[u8]) -> Result<(Type6OpCode, usize), AmlInternalError> {
    match parse_def_deref_of(data) {
        Ok((res, size)) => return Ok((Type6OpCode::DefDerefOf(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_ref_of(data) {
        Ok((res, size)) => return Ok((Type6OpCode::DefRefOf(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_index(data) {
        Ok((res, size)) => return Ok((Type6OpCode::DefIndex(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_method_invocation(data) {
        // UserTermObj is a method call. Would've been nice to be consistent about this...
        Ok((mi, size)) => Ok((Type6OpCode::MethodInvocation(mi), size)),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }
}

pub fn parse_def_package(data: &[u8]) -> Result<(DefPackage, usize), AmlInternalError> {
    if data[0] != 0x12 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let num_elements = data[1 + pkg_length_len];

    let mut current_offset: usize = 2 + pkg_length_len;
    let mut elements: Vec<PackageElement> = vec!();
    
    while current_offset < pkg_length {
        match parse_data_ref_obj(&data[current_offset .. 1 + pkg_length]) {
            Ok((data_ref_obj, data_ref_obj_len)) => {
                elements.push(PackageElement::DataRefObj(data_ref_obj));
                current_offset += data_ref_obj_len;
            },
            Err(AmlInternalError::AmlParseError) => 
                match parse_name_string(&data[current_offset .. 1 + pkg_length]) {
                    Ok((name_string, name_string_len)) => {
                        elements.push(PackageElement::NameString(name_string));
                        current_offset += name_string_len;
                    },
                    Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
                    Err(AmlInternalError::AmlDeferredLoad) => return Ok((DefPackage::DeferredLoad(
                        data[0 .. 1 + pkg_length].to_vec()
                    ), 1 + pkg_length))
                },
            Err(AmlInternalError::AmlDeferredLoad) => return Ok((DefPackage::DeferredLoad(
                data[0 .. 1 + pkg_length].to_vec()
            ), 1 + pkg_length))
        }
    }

    Ok((DefPackage::Package {num_elements, elements}, 1 + pkg_length))
}

pub fn parse_def_var_package(data: &[u8]) -> Result<(DefVarPackage, usize), AmlInternalError> {
    if data[0] != 0x13 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (num_elements, num_elements_len) = parse_term_arg(&data[1 + pkg_length_len ..])?;

    let mut current_offset: usize = 1 + pkg_length_len + num_elements_len;
    let mut elements: Vec<PackageElement> = vec!();
    
    while current_offset < pkg_length {
        match parse_data_ref_obj(&data[current_offset .. 1 + pkg_length]) {
            Ok((data_ref_obj, data_ref_obj_len)) => {
                elements.push(PackageElement::DataRefObj(data_ref_obj));
                current_offset += data_ref_obj_len;
            },
            Err(AmlInternalError::AmlParseError) => 
                match parse_name_string(&data[current_offset .. 1 + pkg_length]) {
                    Ok((name_string, name_string_len)) => {
                        elements.push(PackageElement::NameString(name_string));
                        current_offset += name_string_len;
                    },
                    Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
                    Err(AmlInternalError::AmlDeferredLoad) => return Ok((DefVarPackage::DeferredLoad(
                        data[0 .. 1 + pkg_length].to_vec()
                    ), 1 + pkg_length))
                },
            Err(AmlInternalError::AmlDeferredLoad) => return Ok((DefVarPackage::DeferredLoad(
                data[0 .. 1 + pkg_length].to_vec()
            ), 1 + pkg_length))
        }
    }

    Ok((DefVarPackage::Package {num_elements, elements}, 1 + pkg_length))
}

pub fn parse_def_buffer(data: &[u8]) -> Result<(DefBuffer, usize), AmlInternalError> {
    if data[0] != 0x11 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (buffer_size, buffer_size_len) = match parse_term_arg(&data[1 + pkg_length_len..]) {
        Ok(s) => s,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Ok((DefBuffer::DeferredLoad(
            data[0 .. 1 + pkg_length].to_vec()
        ), 1 + pkg_length))
    };
    let byte_list = data[1 + pkg_length_len + buffer_size_len .. 1 + pkg_length].to_vec();
    
    Ok((DefBuffer::Buffer {buffer_size, byte_list}, pkg_length + 1))
}

fn parse_def_ref_of(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    if data[0] != 0x71 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj_reference, obj_reference_len) = parse_super_name(&data[1..])?;

    Ok((obj_reference, obj_reference_len + 1))
}

fn parse_def_deref_of(data: &[u8]) -> Result<(TermArg, usize), AmlInternalError> {
    if data[0] != 0x83 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj_reference, obj_reference_len) = parse_term_arg(&data[1..])?;

    Ok((obj_reference, obj_reference_len + 1))
}

fn parse_def_acquire(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x23 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (object, object_len) = parse_super_name(&data[2..])?;
    let timeout = (data[2 + object_len] as u16) +
        ((data[3 + object_len] as u16) << 8);
    
    Ok((Type2OpCode::DefAcquire {object, timeout}, object_len + 4))
}

fn parse_def_increment(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x75 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj, obj_len) = parse_super_name(&data[1..])?;
    Ok((Type2OpCode::DefIncrement(obj), obj_len + 1))
}

fn parse_def_index(data: &[u8]) -> Result<(DefIndex, usize), AmlInternalError> {
    if data[0] != 0x88 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj, obj_len) = parse_term_arg(&data[1..])?;
    let (idx, idx_len) = parse_term_arg(&data[1 + obj_len..])?;
    let (target, target_len) = parse_target(&data[1 + obj_len + idx_len..])?;

    Ok((DefIndex {obj, idx, target: Box::new(target)}, 1 + obj_len + idx_len + target_len))
}

fn parse_def_lequal(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x93 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLEqual {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_lless(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x95 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLLess {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_to_hex_string(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x98 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefToHexString {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_to_buffer(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x96 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefToBuffer {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_subtract(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x74 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (minuend, minuend_len) = parse_term_arg(&data[1..])?;
    let (subtrahend, subtrahend_len) = parse_term_arg(&data[1 + minuend_len..])?;
    let (target, target_len) = parse_target(&data[1 + minuend_len + subtrahend_len..])?;

    Ok((Type2OpCode::DefSubtract {minuend, subtrahend, target}, 1 + minuend_len + subtrahend_len + target_len))
}

fn parse_def_size_of(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x87 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (name, name_len) = parse_super_name(&data[1..])?;
    Ok((Type2OpCode::DefSizeOf(name), name_len + 1))
}

fn parse_def_store(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x70 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_super_name(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefStore {operand, target}, operand_len + target_len + 1))
}

fn parse_def_or(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x7D {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefOr {lhs, rhs, target}, 1 + lhs_len + rhs_len))
}

fn parse_def_add(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x72 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefAdd {lhs, rhs, target}, 1 + lhs_len + rhs_len))
}

fn parse_def_and(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x7B {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefAnd {lhs, rhs, target}, 1 + lhs_len + rhs_len))
}

fn parse_def_concat_res(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x84 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefConcatRes {lhs, rhs, target}, 1 + lhs_len + rhs_len))
}

fn parse_def_cond_ref_of(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x12 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (operand, operand_len) = parse_super_name(&data[2..])?;
    let (target, target_len) = parse_target(&data[2 + operand_len..])?;

    Ok((Type2OpCode::DefCondRefOf {operand, target}, 2 + operand_len + target_len))
}

fn parse_def_concat(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x73 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefConcat {lhs, rhs, target}, 1 + lhs_len + rhs_len))
}
