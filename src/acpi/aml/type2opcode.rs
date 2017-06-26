use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;

use super::{AmlInternalError, AmlExecutable, AmlValue, AmlNamespace};
use super::pkglength::parse_pkg_length;
use super::termlist::{parse_term_arg, parse_method_invocation, TermArg, MethodInvocation};
use super::namestring::{parse_super_name, parse_target, parse_name_string, parse_simple_name,
                        SuperName, Target};
use super::dataobj::{parse_data_ref_obj, DataRefObj};

#[derive(Debug, Clone)]
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
    DefDecrement(SuperName),
    DefFindSetLeftBit {
        operand: TermArg,
        target: Target
    },
    DefFindSetRightBit {
        operand: TermArg,
        target: Target
    },
    DefFromBCD {
        operand: TermArg,
        target: Target
    },
    DefDivide {
        dividend: TermArg,
        divisor: TermArg,
        remainder: Target,
        quotient: Target
    },
    DefCondRefOf {
        operand: SuperName,
        target: Target
    },
    DefCopyObject {
        source: TermArg,
        destination: SuperName
    },
    DefLAnd {
        lhs: TermArg,
        rhs: TermArg
    },
    DefLEqual {
        lhs: TermArg,
        rhs: TermArg
    },
    DefLGreater {
        lhs: TermArg,
        rhs: TermArg
    },
    DefLLess {
        lhs: TermArg,
        rhs: TermArg
    },
    DefLNot(TermArg),
    DefLOr {
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
    DefToBCD {
        operand: TermArg,
        target: Target
    },
    DefToDecimalString {
        operand: TermArg,
        target: Target
    },
    DefToInteger {
        operand: TermArg,
        target: Target
    },
    DefToString {
        operand: TermArg,
        length: TermArg,
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
    DefShiftLeft {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefShiftRight {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefAdd {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefMultiply {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefMod {
        dividend: TermArg,
        divisor: TermArg,
        target: Target
    },
    DefAnd {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefNAnd {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefOr {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefXor {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefNOr {
        lhs: TermArg,
        rhs: TermArg,
        target: Target
    },
    DefNot {
        operand: TermArg,
        target: Target
    },
    DefLoadTable {
        signature: TermArg,
        oem_id: TermArg,
        oem_table_id: TermArg,
        root_path: TermArg,
        parameter_path: TermArg,
        parameter_data: TermArg
    },
    DefMatch {
        search_pkg: TermArg,
        first_operation: MatchOpcode,
        first_operand: TermArg,
        second_operation: MatchOpcode,
        second_operand: TermArg,
        start_index: TermArg
    },
    DefMid {
        source: TermArg,
        index: TermArg,
        length: TermArg,
        target: Target
    },
    DefWait {
        event_object: SuperName,
        operand: TermArg
    },
    DefObjectType(DefObjectType),
    DefTimer,
    MethodInvocation(MethodInvocation)
}

impl AmlExecutable for Type2OpCode {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue> {
        None
    }
}

#[derive(Debug, Clone)]
pub enum DefObjectType {
    SuperName(SuperName),
    DefIndex(DefIndex),
    DefRefOf(SuperName),
    DefDerefOf(TermArg)
}

#[derive(Debug, Clone)]
pub enum MatchOpcode {
    MTR,
    MEQ,
    MLE,
    MLT,
    MGE,
    MGT
}

#[derive(Debug, Clone)]
pub enum Type6OpCode {
    DefDerefOf(TermArg),
    DefRefOf(Box<SuperName>),
    DefIndex(DefIndex),
    MethodInvocation(MethodInvocation)
}

#[derive(Debug, Clone)]
pub struct DefIndex {
    obj: TermArg,
    idx: TermArg,
    target: Box<Target>
}

#[derive(Debug, Clone)]
pub enum DefBuffer {
    Buffer {
        buffer_size: TermArg,
        byte_list: Vec<u8>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug, Clone)]
pub enum DefPackage {
    Package {
        num_elements: u8,
        elements: Vec<PackageElement>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug, Clone)]
pub enum DefVarPackage {
    Package {
        num_elements: TermArg,
        elements: Vec<PackageElement>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug, Clone)]
pub enum PackageElement {
    DataRefObj(DataRefObj),
    NameString(String)
}

impl AmlExecutable for DefPackage {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue> {
        match *self {
            DefPackage::Package { ref num_elements, ref elements } => {
                let mut values: Vec<AmlValue> = vec!();

                for element in elements {
                    match *element {
                        PackageElement::DataRefObj(ref d) => {
                            let elem = match d.execute(namespace, scope.clone()) {
                                Some(e) => e,
                                None => continue
                            };

                            values.push(elem);
                        },
                        _ => return None
                    }
                }

                Some(AmlValue::Package(values))
            },
            _ => None
        }
    }
}

pub fn parse_type2_opcode(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_selector! {
        data,
        parse_def_increment,
        parse_def_acquire,
        parse_def_wait,
        parse_def_land,
        parse_def_lequal,
        parse_def_lgreater,
        parse_def_lless,
        parse_def_lnot,
        parse_def_lor,
        parse_def_size_of,
        parse_def_store,
        parse_def_subtract,
        parse_def_to_buffer,
        parse_def_to_hex_string,
        parse_def_to_bcd,
        parse_def_to_decimal_string,
        parse_def_to_integer,
        parse_def_to_string,
        parse_def_add,
        parse_def_xor,
        parse_def_shift_left,
        parse_def_shift_right,
        parse_def_mod,
        parse_def_and,
        parse_def_or,
        parse_def_concat_res,
        parse_def_concat,
        parse_def_cond_ref_of,
        parse_def_copy_object,
        parse_def_decrement,
        parse_def_divide,
        parse_def_find_set_left_bit,
        parse_def_find_set_right_bit,
        parse_def_from_bcd,
        parse_def_load_table,
        parse_def_match,
        parse_def_mid,
        parse_def_multiply,
        parse_def_nand,
        parse_def_nor,
        parse_def_not,
        parse_def_timer,
        parser_wrap!(Type2OpCode::DefBuffer, parse_def_buffer),
        parser_wrap!(Type2OpCode::DefPackage, parse_def_package),
        parser_wrap!(Type2OpCode::DefVarPackage, parse_def_var_package),
        parser_wrap!(Type2OpCode::DefObjectType, parse_def_object_type),
        parser_wrap!(Type2OpCode::DefDerefOf, parse_def_deref_of),
        parser_wrap!(Type2OpCode::DefRefOf, parse_def_ref_of),
        parser_wrap!(Type2OpCode::DefIndex, parse_def_index),
        parser_wrap!(Type2OpCode::MethodInvocation, parse_method_invocation)
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_type6_opcode(data: &[u8]) -> Result<(Type6OpCode, usize), AmlInternalError> {
    parser_selector! {
        data,
        parser_wrap!(Type6OpCode::DefDerefOf, parse_def_deref_of),
        parser_wrap!(Type6OpCode::DefRefOf, parser_wrap!(Box::new, parse_def_ref_of)),
        parser_wrap!(Type6OpCode::DefIndex, parse_def_index),
        parser_wrap!(Type6OpCode::MethodInvocation, parse_method_invocation)
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_def_object_type(data: &[u8]) -> Result<(DefObjectType, usize), AmlInternalError> {
    parser_opcode!(data, 0x8E);
    parser_selector! {
        data,
        parser_wrap!(DefObjectType::SuperName, parse_super_name),
        parser_wrap!(DefObjectType::DefRefOf, parse_def_ref_of),
        parser_wrap!(DefObjectType::DefDerefOf, parse_def_deref_of),
        parser_wrap!(DefObjectType::DefIndex, parse_def_index)
    }

    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_def_package(data: &[u8]) -> Result<(DefPackage, usize), AmlInternalError> {
    parser_opcode!(data, 0x12);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let num_elements = data[1 + pkg_length_len];

    let elements = match parse_package_elements_list(&data[2 + pkg_length_len .. 1 + pkg_length]) {
        Ok(e) => e,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((DefPackage::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 1 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((DefPackage::Package {num_elements, elements}, 1 + pkg_length))
}

pub fn parse_def_var_package(data: &[u8]) -> Result<(DefVarPackage, usize), AmlInternalError> {
    parser_opcode!(data, 0x13);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (num_elements, num_elements_len) = parse_term_arg(&data[1 + pkg_length_len ..])?;

    let elements = match parse_package_elements_list(&data[1 + pkg_length_len + num_elements_len ..
                                                           1 + pkg_length]) {
        Ok(e) => e,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((DefVarPackage::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()),
                       1 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((DefVarPackage::Package {num_elements, elements}, 1 + pkg_length))
}

fn parse_package_elements_list(data: &[u8]) -> Result<Vec<PackageElement>, AmlInternalError> {
    let mut current_offset: usize = 0;
    let mut elements: Vec<PackageElement> = vec!();

    while current_offset < data.len() {
        match parse_data_ref_obj(&data[current_offset ..]) {
            Ok((data_ref_obj, data_ref_obj_len)) => {
                elements.push(PackageElement::DataRefObj(data_ref_obj));
                current_offset += data_ref_obj_len;
            },
            Err(AmlInternalError::AmlInvalidOpCode) =>
                match parse_name_string(&data[current_offset ..]) {
                    Ok((name_string, name_string_len)) => {
                        elements.push(PackageElement::NameString(name_string));
                        current_offset += name_string_len;
                    },
                    Err(e) => return Err(e)
                },
            Err(e) => return Err(e)
        }
    }

    Ok(elements)
}

pub fn parse_def_buffer(data: &[u8]) -> Result<(DefBuffer, usize), AmlInternalError> {
    parser_opcode!(data, 0x11);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (buffer_size, buffer_size_len) = match parse_term_arg(&data[1 + pkg_length_len..]) {
        Ok(s) => s,
        Err(AmlInternalError::AmlDeferredLoad) => return Ok((DefBuffer::DeferredLoad(
            data[0 .. 1 + pkg_length].to_vec()
        ), 1 + pkg_length)),
        Err(e) => return Err(e),
    };
    let byte_list = data[1 + pkg_length_len + buffer_size_len .. 1 + pkg_length].to_vec();

    Ok((DefBuffer::Buffer {buffer_size, byte_list}, pkg_length + 1))
}

fn parse_def_ref_of(data: &[u8]) -> Result<(SuperName, usize), AmlInternalError> {
    parser_opcode!(data, 0x71);
    let (obj_reference, obj_reference_len) = parse_super_name(&data[1..])?;

    Ok((obj_reference, obj_reference_len + 1))
}

fn parse_def_deref_of(data: &[u8]) -> Result<(TermArg, usize), AmlInternalError> {
    parser_opcode!(data, 0x83);
    let (obj_reference, obj_reference_len) = parse_term_arg(&data[1..])?;

    Ok((obj_reference, obj_reference_len + 1))
}

fn parse_def_acquire(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x23);

    let (object, object_len) = parse_super_name(&data[2..])?;
    let timeout = (data[2 + object_len] as u16) +
        ((data[3 + object_len] as u16) << 8);

    Ok((Type2OpCode::DefAcquire {object, timeout}, object_len + 4))
}

fn parse_def_increment(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x75);

    let (obj, obj_len) = parse_super_name(&data[1..])?;
    Ok((Type2OpCode::DefIncrement(obj), obj_len + 1))
}

fn parse_def_index(data: &[u8]) -> Result<(DefIndex, usize), AmlInternalError> {
    parser_opcode!(data, 0x88);

    let (obj, obj_len) = parse_term_arg(&data[1..])?;
    let (idx, idx_len) = parse_term_arg(&data[1 + obj_len..])?;
    let (target, target_len) = parse_target(&data[1 + obj_len + idx_len..])?;

    Ok((DefIndex {obj, idx, target: Box::new(target)}, 1 + obj_len + idx_len + target_len))
}

fn parse_def_land(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x90);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLAnd {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_lequal(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x93);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLEqual {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_lgreater(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x94);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLGreater {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_lless(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x95);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLLess {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_lnot(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x92);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;

    Ok((Type2OpCode::DefLNot(operand), 1 + operand_len))
}

fn parse_def_lor(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x91);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;

    Ok((Type2OpCode::DefLOr {lhs, rhs}, 1 + lhs_len + rhs_len))
}

fn parse_def_to_hex_string(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x98);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefToHexString {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_to_buffer(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x96);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefToBuffer {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_to_bcd(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x29);

    let (operand, operand_len) = parse_term_arg(&data[2..])?;
    let (target, target_len) = parse_target(&data[2 + operand_len..])?;

    Ok((Type2OpCode::DefToBCD {operand, target}, 2 + operand_len + target_len))
}

fn parse_def_to_decimal_string(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x97);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefToDecimalString {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_to_integer(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x99);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefToInteger {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_to_string(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x9C);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (length, length_len) = parse_term_arg(&data[1 + operand_len..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len + length_len..])?;

    Ok((Type2OpCode::DefToString {operand, length, target}, 1 + operand_len + length_len + target_len))
}

fn parse_def_subtract(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x74);

    let (minuend, minuend_len) = parse_term_arg(&data[1..])?;
    let (subtrahend, subtrahend_len) = parse_term_arg(&data[1 + minuend_len..])?;
    let (target, target_len) = parse_target(&data[1 + minuend_len + subtrahend_len..])?;

    Ok((Type2OpCode::DefSubtract {minuend, subtrahend, target}, 1 + minuend_len + subtrahend_len + target_len))
}

fn parse_def_size_of(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x87);

    let (name, name_len) = parse_super_name(&data[1..])?;
    Ok((Type2OpCode::DefSizeOf(name), name_len + 1))
}

fn parse_def_store(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x70);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_super_name(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefStore {operand, target}, operand_len + target_len + 1))
}

fn parse_def_or(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x7D);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefOr {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_shift_left(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x79);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefShiftLeft {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_shift_right(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x7A);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefShiftRight {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_add(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x72);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefAdd {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_and(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x7B);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefAnd {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_xor(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x7F);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefXor {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_concat_res(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x84);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefConcatRes {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_wait(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x25);

    let (event_object, event_object_len) = parse_super_name(&data[2..])?;
    let (operand, operand_len) = parse_term_arg(&data[2 + event_object_len..])?;


    Ok((Type2OpCode::DefWait {event_object, operand}, 2 + event_object_len + operand_len))
}

fn parse_def_cond_ref_of(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x12);

    let (operand, operand_len) = parse_super_name(&data[2..])?;
    let (target, target_len) = parse_target(&data[2 + operand_len..])?;

    Ok((Type2OpCode::DefCondRefOf {operand, target}, 2 + operand_len + target_len))
}

fn parse_def_copy_object(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x9D);

    let (source, source_len) = parse_term_arg(&data[1..])?;
    let (destination, destination_len) = parse_simple_name(&data[1 + source_len..])?;

    Ok((Type2OpCode::DefCopyObject {source, destination}, 1 + source_len + destination_len))
}

fn parse_def_concat(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x73);

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefConcat {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_decrement(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x76);

    let (target, target_len) = parse_super_name(&data[1..])?;

    Ok((Type2OpCode::DefDecrement(target), 1 + target_len))
}

fn parse_def_divide(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x78);

    let (dividend, dividend_len) = parse_term_arg(&data[1..])?;
    let (divisor, divisor_len) = parse_term_arg(&data[1 + dividend_len..])?;
    let (remainder, remainder_len) = parse_target(&data[1 + dividend_len + divisor_len..])?;
    let (quotient, quotient_len) = parse_target(&data[1 + dividend_len + divisor_len + remainder_len..])?;

    Ok((Type2OpCode::DefDivide {dividend, divisor, remainder, quotient},
        1 + dividend_len + divisor_len + remainder_len + quotient_len))
}

fn parse_def_find_set_left_bit(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    parser_opcode!(data, 0x81);

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefFindSetLeftBit {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_find_set_right_bit(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x82 {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefFindSetRightBit {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_load_table(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x1F {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (signature, signature_len) = parse_term_arg(&data[2..])?;
    let (oem_id, oem_id_len) = parse_term_arg(&data[2 + signature_len..])?;
    let (oem_table_id, oem_table_id_len) = parse_term_arg(&data[2 + signature_len + oem_id_len..])?;
    let (root_path, root_path_len) =
        parse_term_arg(&data[2 + signature_len + oem_id_len + oem_table_id_len..])?;
    let (parameter_path, parameter_path_len) =
        parse_term_arg(&data[2 + signature_len + oem_id_len + oem_table_id_len + root_path_len..])?;
    let (parameter_data, parameter_data_len) =
        parse_term_arg(&data[2 + signature_len + oem_id_len + oem_table_id_len + root_path_len +
                             parameter_path_len..])?;

    Ok((Type2OpCode::DefLoadTable {signature, oem_id, oem_table_id, root_path,
                                   parameter_path, parameter_data},
        2 + signature_len + oem_id_len + oem_table_id_len + root_path_len +
        parameter_path_len + parameter_data_len))
}

fn parse_def_match(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x89 {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (search_pkg, search_pkg_len) = parse_term_arg(&data[1..])?;
    let first_operation = match data[1 + search_pkg_len] {
        0 => MatchOpcode::MTR,
        1 => MatchOpcode::MEQ,
        2 => MatchOpcode::MLE,
        3 => MatchOpcode::MLT,
        4 => MatchOpcode::MGE,
        5 => MatchOpcode::MGT,
        _ => return Err(AmlInternalError::AmlParseError("DefMatch - Invalid Opcode"))
    };
    let (first_operand, first_operand_len) = parse_term_arg(&data[2 + search_pkg_len..])?;

    let second_operation = match data[2 + search_pkg_len + first_operand_len] {
        0 => MatchOpcode::MTR,
        1 => MatchOpcode::MEQ,
        2 => MatchOpcode::MLE,
        3 => MatchOpcode::MLT,
        4 => MatchOpcode::MGE,
        5 => MatchOpcode::MGT,
        _ => return Err(AmlInternalError::AmlParseError("DefMatch - Invalid Opcode"))
    };
    let (second_operand, second_operand_len) =
        parse_term_arg(&data[3 + search_pkg_len + first_operand_len..])?;

    let (start_index, start_index_len) =
        parse_term_arg(&data[3 + search_pkg_len + first_operand_len + second_operand_len..])?;

    Ok((Type2OpCode::DefMatch {search_pkg, first_operation, first_operand,
                               second_operation, second_operand, start_index},
        3 + search_pkg_len + first_operand_len + second_operand_len + start_index_len))
}

fn parse_def_from_bcd(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x28 {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (operand, operand_len) = parse_term_arg(&data[2..])?;
    let (target, target_len) = parse_target(&data[2 + operand_len..])?;

    Ok((Type2OpCode::DefFromBCD {operand, target}, 2 + operand_len + target_len))
}

fn parse_def_mid(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x9E {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (source, source_len) = parse_term_arg(&data[1..])?;
    let (index, index_len) = parse_term_arg(&data[1 + source_len..])?;
    let (length, length_len) = parse_term_arg(&data[1 + source_len + index_len..])?;
    let (target, target_len) = parse_target(&data[1 + source_len + index_len + length_len..])?;

    Ok((Type2OpCode::DefMid {source, index, length, target},
        1 + source_len + index_len + length_len + target_len))
}

fn parse_def_mod(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x85 {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (dividend, dividend_len) = parse_term_arg(&data[1..])?;
    let (divisor, divisor_len) = parse_term_arg(&data[1 + dividend_len..])?;
    let (target, target_len) = parse_target(&data[1 + dividend_len + divisor_len..])?;

    Ok((Type2OpCode::DefMod {dividend, divisor, target}, 1 + dividend_len + divisor_len + target_len))
}

fn parse_def_multiply(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x77 {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefMultiply {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_nand(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x7C {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefNAnd {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_nor(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x7E {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (lhs, lhs_len) = parse_term_arg(&data[1..])?;
    let (rhs, rhs_len) = parse_term_arg(&data[1 + lhs_len..])?;
    let (target, target_len) = parse_target(&data[1 + lhs_len + rhs_len..])?;

    Ok((Type2OpCode::DefNOr {lhs, rhs, target}, 1 + lhs_len + rhs_len + target_len))
}

fn parse_def_not(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x80 {
        return Err(AmlInternalError::AmlInvalidOpCode);
    }

    let (operand, operand_len) = parse_term_arg(&data[1..])?;
    let (target, target_len) = parse_target(&data[1 + operand_len..])?;

    Ok((Type2OpCode::DefNot {operand, target}, 1 + operand_len + target_len))
}

fn parse_def_timer(data: &[u8]) -> Result<(Type2OpCode, usize), AmlInternalError> {
    if data[0] != 0x5B || data[1] != 0x33 {
        return Err(AmlInternalError::AmlInvalidOpCode)
    }

    Ok((Type2OpCode::DefTimer, 2 as usize))
}
