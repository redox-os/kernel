use collections::vec::Vec;

use super::AmlInternalError;

use super::pkglength::parse_pkg_length;
use super::termlist::{parse_term_arg, parse_method_invocation, TermArg, MethodInvocation};
use super::namestring::{parse_super_name, parse_target, SuperName, Target};

pub enum Type2OpCode {
    DefBuffer {
        buffer_size: TermArg,
        byte_list: Vec<u8>
    },
    DefDerefOf(TermArg),
    DefIncrement(SuperName),
    DefIndex {
        obj: TermArg,
        idx: TermArg,
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
    DefOr {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    MethodInvocation(MethodInvocation),
    DeferredLoad(Vec<u8>)
}

pub fn parse_type2_opcode(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    match parse_def_buffer(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_deref_of(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_increment(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_def_index(data) {
        Ok(res) => return Ok(res),
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

    match parse_def_or(data) {
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

fn parse_def_buffer(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x11 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (buffer_size, buffer_size_len) = match parse_term_arg(&data[1 + pkg_length_len..]) {
        Ok(s) => s,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => return Ok((Type2OpCode::DeferredLoad(
            data[0 .. 1 + pkg_length].to_vec()
        ), 1 + pkg_length))
    };
    let byte_list = data[1 + pkg_length_len + buffer_size_len .. 1 + pkg_length].to_vec();
    
    Ok((Type2OpCode::DefBuffer {buffer_size, byte_list}, pkg_length + 1))
}


fn parse_def_deref_of(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x83 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj_reference, obj_reference_len) = parse_term_arg(&data[1..])?;

    Ok((Type2OpCode::DefDerefOf(obj_reference), obj_reference_len + 1))
}

fn parse_def_increment(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x75 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj, obj_len) = parse_super_name(&data[1..])?;
    Ok((Type2OpCode::DefIncrement(obj), obj_len + 1))
}

fn parse_def_index(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x88 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (obj, obj_len) = parse_term_arg(&data[1..])?;
    let (idx, idx_len) = parse_term_arg(&data[1 + obj_len..])?;
    let (target, target_len) = parse_target(&data[1 + obj_len + idx_len..])?;

    Ok((Type2OpCode::DefIndex {obj, idx, target}, 1 + obj_len + idx_len + target_len))
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
