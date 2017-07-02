use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;

use super::AmlError;
use super::parser::{AmlParseType, ParseResult};
use super::namespace::{AmlValue, ObjectReference};
use super::pkglength::parse_pkg_length;
use super::termlist::{parse_term_arg, parse_method_invocation};
use super::namestring::{parse_super_name, parse_target, parse_name_string, parse_simple_name};
use super::dataobj::parse_data_ref_obj;

#[derive(Debug, Clone)]
pub enum MatchOpcode {
    MTR,
    MEQ,
    MLE,
    MLT,
    MGE,
    MGT
}

pub fn parse_type2_opcode(data: &[u8],
                          namespace: &mut BTreeMap<String, AmlValue>,
                          scope: String) -> ParseResult {
    parser_selector! {
        data, namespace, scope.clone(),
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
        parse_def_buffer,
        parse_def_package,
        parse_def_var_package,
        parse_def_object_type,
        parse_def_deref_of,
        parse_def_ref_of,
        parse_def_index,
        parse_method_invocation
    };

    Err(AmlError::AmlInvalidOpCode)
}

pub fn parse_type6_opcode(data: &[u8],
                          namespace: &mut BTreeMap<String, AmlValue>,
                          scope: String) -> ParseResult {
    parser_selector! {
        data, namespace, scope.clone(),
        parse_def_deref_of,
        parse_def_ref_of,
        parse_def_index,
        parse_method_invocation
    };

    Err(AmlError::AmlInvalidOpCode)
}

pub fn parse_def_object_type(data: &[u8],
                             namespace: &mut BTreeMap<String, AmlValue>,
                             scope: String) -> ParseResult {
    parser_opcode!(data, 0x8E);
    parser_selector! {
        data, namespace, scope.clone(),
        parse_super_name,
        parse_def_ref_of,
        parse_def_deref_of,
        parse_def_index
    }

    Err(AmlError::AmlInvalidOpCode)
}

pub fn parse_def_package(data: &[u8],
                         namespace: &mut BTreeMap<String, AmlValue>,
                         scope: String) -> ParseResult {
    // TODO: Handle deferred loads in here
    // TODO: Truncate/extend array if necessary
    parser_opcode!(data, 0x12);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let num_elements = data[1 + pkg_length_len];
    let elements = parse_package_elements_list(&data[2 + pkg_length_len .. 1 + pkg_length],
                                               namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: elements.val,
        len: 1 + pkg_length
    })
}

pub fn parse_def_var_package(data: &[u8],
                             namespace: &mut BTreeMap<String, AmlValue>,
                             scope: String) -> ParseResult {
    // TODO: Handle deferred loads in here
    // TODO: Truncate/extend array if necessary
    parser_opcode!(data, 0x13);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let num_elements = parse_term_arg(&data[1 + pkg_length_len .. 1 + pkg_length], namespace, scope.clone())?;
    let elements = parse_package_elements_list(&data[1 + pkg_length_len + num_elements.len ..
                                                     1 + pkg_length], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: elements.val,
        len: 1 + pkg_length
    })
}

fn parse_package_elements_list(data: &[u8],
                               namespace: &mut BTreeMap<String, AmlValue>,
                               scope: String) -> ParseResult {
    let mut current_offset: usize = 0;
    let mut elements: Vec<AmlValue> = vec!();

    while current_offset < data.len() {
        let dro = if let Ok(e) = parse_data_ref_obj(&data[current_offset..], namespace, scope.clone()) {
            e
        } else {
            parse_name_string(&data[current_offset..], namespace, scope.clone())?
        };

        elements.push(dro.val);
        current_offset += dro.len;
    }

    Ok(AmlParseType {
        val: AmlValue::Package(elements),
        len: data.len()
    })
}

pub fn parse_def_buffer(data: &[u8],
                       namespace: &mut BTreeMap<String, AmlValue>,
                       scope: String) -> ParseResult {
    // TODO: Perform computation
    parser_opcode!(data, 0x11);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let buffer_size = parse_term_arg(&data[1 + pkg_length_len..], namespace, scope.clone())?;
    let byte_list = data[1 + pkg_length_len + buffer_size.len .. 1 + pkg_length].to_vec();

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + pkg_length
    })
}

fn parse_def_ref_of(data: &[u8],
                       namespace: &mut BTreeMap<String, AmlValue>,
                       scope: String) -> ParseResult {
    // TODO: Perform computation
    parser_opcode!(data, 0x71);

    let obj = parse_super_name(&data[1..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + obj.len
    })
}

fn parse_def_deref_of(data: &[u8],
                      namespace: &mut BTreeMap<String, AmlValue>,
                      scope: String) -> ParseResult {
    // TODO: Perform computation
    parser_opcode!(data, 0x83);

    let obj = parse_term_arg(&data[1..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + obj.len
    })
}

fn parse_def_acquire(data: &[u8],
                     namespace: &mut BTreeMap<String, AmlValue>,
                     scope: String) -> ParseResult {
    // TODO: Store the result
    // TODO: Perform computation
    parser_opcode_extended!(data, 0x23);

    let obj = parse_super_name(&data[1..], namespace, scope.clone())?;
    let timeout = (data[2 + obj.len] as u16) + ((data[3 + obj.len] as u16) << 8);
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 4 + obj.len
    })
}

fn parse_def_increment(data: &[u8],
                       namespace: &mut BTreeMap<String, AmlValue>,
                       scope: String) -> ParseResult {
    // TODO: Store the result
    // TODO: Perform computation
    parser_opcode!(data, 0x75);

    let obj = parse_super_name(&data[1..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + obj.len
    })
}

fn parse_def_index(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    // TODO: Perform computation
    parser_opcode!(data, 0x88);

    let obj = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let idx = parse_term_arg(&data[1 + obj.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + obj.len + idx.len..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + obj.len + idx.len + target.len
    })
}

fn parse_def_land(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    parser_opcode!(data, 0x90);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;

    let result = if lhs.val.get_as_integer()? > 0 && rhs.val.get_as_integer()? > 0 { 1 } else { 0 };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len
    })
}

fn parse_def_lequal(data: &[u8],
                    namespace: &mut BTreeMap<String, AmlValue>,
                    scope: String) -> ParseResult {
    parser_opcode!(data, 0x93);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;

    let result = if lhs.val.get_as_integer()? == rhs.val.get_as_integer()? { 1 } else { 0 };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len
    })
}

fn parse_def_lgreater(data: &[u8],
                      namespace: &mut BTreeMap<String, AmlValue>,
                      scope: String) -> ParseResult {
    parser_opcode!(data, 0x94);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;

    let result = if lhs.val.get_as_integer()? > rhs.val.get_as_integer()? { 1 } else { 0 };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len
    })
}

fn parse_def_lless(data: &[u8],
                   namespace: &mut BTreeMap<String, AmlValue>,
                   scope: String) -> ParseResult {
    parser_opcode!(data, 0x95);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;

    let result = if lhs.val.get_as_integer()? < rhs.val.get_as_integer()? { 1 } else { 0 };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len
    })
}

fn parse_def_lnot(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    parser_opcode!(data, 0x92);

    let operand = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let result = if operand.val.get_as_integer()? == 0 { 1 } else { 0 };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + operand.len
    })
}

fn parse_def_lor(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    parser_opcode!(data, 0x91);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;

    let result = if lhs.val.get_as_integer()? > 0 || rhs.val.get_as_integer()? > 0 { 1 } else { 0 };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len
    })
}

fn parse_def_to_hex_string(data: &[u8],
                           namespace: &mut BTreeMap<String, AmlValue>,
                           scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x98);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_to_buffer(data: &[u8],
                       namespace: &mut BTreeMap<String, AmlValue>,
                       scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x96);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_to_bcd(data: &[u8],
                    namespace: &mut BTreeMap<String, AmlValue>,
                    scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode_extended!(data, 0x29);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_to_decimal_string(data: &[u8],
                               namespace: &mut BTreeMap<String, AmlValue>,
                               scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x97);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_to_integer(data: &[u8],
                        namespace: &mut BTreeMap<String, AmlValue>,
                        scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x99);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_to_string(data: &[u8],
                       namespace: &mut BTreeMap<String, AmlValue>,
                       scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x9C);

    let operand = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let length = parse_term_arg(&data[1 + operand.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + operand.len + length.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + length.len + target.len
    })
}

fn parse_def_subtract(data: &[u8],
                      namespace: &mut BTreeMap<String, AmlValue>,
                      scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x74);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;

    let result = lhs.val.get_as_integer()? - rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_size_of(data: &[u8],
                     namespace: &mut BTreeMap<String, AmlValue>,
                     scope: String) -> ParseResult {
    // TODO: Perform the computation
    parser_opcode!(data, 0x87);

    let name = parse_super_name(&data[1..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + name.len
    })
}

fn parse_def_store(data: &[u8],
                   namespace: &mut BTreeMap<String, AmlValue>,
                   scope: String) -> ParseResult {
    // TODO: Perform the store
    parser_opcode!(data, 0x70);

    let operand = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let target = parse_super_name(&data[1 + operand.len..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_or(data: &[u8],
                namespace: &mut BTreeMap<String, AmlValue>,
                scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x7D);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    let result = lhs.val.get_as_integer()? | rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_shift_left(data: &[u8],
                        namespace: &mut BTreeMap<String, AmlValue>,
                        scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x79);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    let result = lhs.val.get_as_integer()? >> rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_shift_right(data: &[u8],
                         namespace: &mut BTreeMap<String, AmlValue>,
                         scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x7A);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    let result = lhs.val.get_as_integer()? << rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_add(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x72);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    let result = lhs.val.get_as_integer()? + rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_and(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x7B);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    let result = lhs.val.get_as_integer()? & rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_xor(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x7F);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    let result = lhs.val.get_as_integer()? ^ rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_concat_res(data: &[u8],
                        namespace: &mut BTreeMap<String, AmlValue>,
                        scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x84);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_wait(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    // TODO: Compute the result
    parser_opcode_extended!(data, 0x25);

    let event_object = parse_super_name(&data[2..], namespace, scope.clone())?;
    let operand = parse_term_arg(&data[2 + event_object.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 2 + event_object.len + operand.len
    })
}

fn parse_def_cond_ref_of(data: &[u8],
                         namespace: &mut BTreeMap<String, AmlValue>,
                         scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result
    parser_opcode_extended!(data, 0x12);

    let operand = parse_super_name(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 2 + operand.len + target.len
    })
}

fn parse_def_copy_object(data: &[u8],
                         namespace: &mut BTreeMap<String, AmlValue>,
                         scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result
    parser_opcode!(data, 0x9D);

    let source = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let destination = parse_simple_name(&data[1 + source.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + source.len + destination.len
    })
}

fn parse_def_concat(data: &[u8],
                    namespace: &mut BTreeMap<String, AmlValue>,
                    scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result
    parser_opcode!(data, 0x73);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_decrement(data: &[u8],
                       namespace: &mut BTreeMap<String, AmlValue>,
                       scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result
    parser_opcode!(data, 0x76);

    let target = parse_super_name(&data[1..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + target.len
    })
}

fn parse_def_divide(data: &[u8],
                    namespace: &mut BTreeMap<String, AmlValue>,
                    scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x78);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target_remainder = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;
    let target_quotient = parse_target(&data[1 + lhs.len + rhs.len + target_remainder.len..], namespace, scope.clone())?;
    
    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + lhs.len + rhs.len + target_remainder.len + target_quotient.len
    })
}

fn parse_def_find_set_left_bit(data: &[u8],
                               namespace: &mut BTreeMap<String, AmlValue>,
                               scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x81);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_find_set_right_bit(data: &[u8],
                                namespace: &mut BTreeMap<String, AmlValue>,
                                scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x82);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + operand.len + target.len
    })
}

fn parse_def_load_table(data: &[u8],
                        namespace: &mut BTreeMap<String, AmlValue>,
                        scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    // TODO: Clean up
    parser_opcode_extended!(data, 0x1F);

    let signature = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let oem_id = parse_term_arg(&data[2 + signature.len..], namespace, scope.clone())?;
    let oem_table_id = parse_term_arg(&data[2 + signature.len + oem_id.len..], namespace, scope.clone())?;
    let root_path = parse_term_arg(&data[2 + signature.len + oem_id.len + oem_table_id.len..], namespace, scope.clone())?;
    let parameter_path = parse_term_arg(&data[2 + signature.len + oem_id.len + oem_table_id.len + root_path.len..], namespace, scope.clone())?;
    let parameter_data = parse_term_arg(&data[2 + signature.len + oem_id.len + oem_table_id.len + root_path.len + parameter_path.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 2 + signature.len + oem_id.len + oem_table_id.len + root_path.len + parameter_path.len + parameter_data.len
    })
}

fn parse_def_match(data: &[u8],
                   namespace: &mut BTreeMap<String, AmlValue>,
                   scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    // TODO: Clean up match blocks
    parser_opcode!(data, 0x28);
    
    let search_pkg = parse_term_arg(&data[1..], namespace, scope.clone())?;
    
    let first_operation = match data[1 + search_pkg.len] {
        0 => MatchOpcode::MTR,
        1 => MatchOpcode::MEQ,
        2 => MatchOpcode::MLE,
        3 => MatchOpcode::MLT,
        4 => MatchOpcode::MGE,
        5 => MatchOpcode::MGT,
        _ => return Err(AmlError::AmlParseError("DefMatch - Invalid Opcode"))
    };
    let first_operand = parse_term_arg(&data[2 + search_pkg.len..], namespace, scope.clone())?;

    let second_operation = match data[2 + search_pkg.len + first_operand.len] {
        0 => MatchOpcode::MTR,
        1 => MatchOpcode::MEQ,
        2 => MatchOpcode::MLE,
        3 => MatchOpcode::MLT,
        4 => MatchOpcode::MGE,
        5 => MatchOpcode::MGT,
        _ => return Err(AmlError::AmlParseError("DefMatch - Invalid Opcode"))
    };
    let second_operand = parse_term_arg(&data[3 + search_pkg.len + first_operand.len..], namespace, scope.clone())?;
    
    let start_index = parse_term_arg(&data[3 + search_pkg.len + first_operand.len + second_operand.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 3 + search_pkg.len + first_operand.len + second_operand.len + start_index.len
    })
}

fn parse_def_from_bcd(data: &[u8],
                      namespace: &mut BTreeMap<String, AmlValue>,
                      scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    // TODO: Clean up match block
    parser_opcode_extended!(data, 0x28);

    let operand = parse_term_arg(&data[2..], namespace, scope.clone())?;
    let target = parse_target(&data[2 + operand.len..], namespace, scope.clone())?;
    
    let result = match target.val.get_as_integer() {
        Ok(i) => {
            let mut i = i;
            let mut ires = 0;

            while i != 0 {
                if i & 0x0F > 10 {
                    return Err(AmlError::AmlValueError);
                }

                ires *= 10;
                ires += i & 0x0F;
                i >>= 4;
            }

            ires
        },
        Err(e) => return Err(e)
    };
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 2 + operand.len + target.len
    })
}

fn parse_def_mid(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Compute the result
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x9E);

    let source = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let index = parse_term_arg(&data[1 + source.len..], namespace, scope.clone())?;
    let length = parse_term_arg(&data[1 + source.len + index.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + source.len + index.len + length.len..], namespace, scope.clone())?;

    Ok(AmlParseType {
        val: AmlValue::Uninitialized,
        len: 1 + source.len + index.len + length.len + target.len
    })
}

fn parse_def_mod(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    // TODO: Fatal exception on rhs == 0
    parser_opcode!(data, 0x85);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;

    let result = lhs.val.get_as_integer()? % rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_multiply(data: &[u8],
                      namespace: &mut BTreeMap<String, AmlValue>,
                      scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    // TODO: Handle overflow
    parser_opcode!(data, 0x77);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;

    let result = lhs.val.get_as_integer()? * rhs.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_nand(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x7C);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;

    let result = !(lhs.val.get_as_integer()? & rhs.val.get_as_integer()?);
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_nor(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x7E);

    let lhs = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let rhs = parse_term_arg(&data[1 + lhs.len..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + lhs.len + rhs.len..], namespace, scope.clone())?;

    let result = !(lhs.val.get_as_integer()? | rhs.val.get_as_integer()?);
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + lhs.len + rhs.len + target.len
    })
}

fn parse_def_not(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    // TODO: Store the result, if appropriate
    parser_opcode!(data, 0x80);

    let operand = parse_term_arg(&data[1..], namespace, scope.clone())?;
    let target = parse_target(&data[1 + operand.len..], namespace, scope.clone())?;

    let result = !operand.val.get_as_integer()?;
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(result),
        len: 1 + operand.len + target.len
    })
}

fn parse_def_timer(data: &[u8],
                   namespace: &mut BTreeMap<String, AmlValue>,
                   scope: String) -> ParseResult {
    // TODO: Read from the hardware timer, and split into 100ns intervals
    parser_opcode_extended!(data, 0x33);
    
    Ok(AmlParseType {
        val: AmlValue::IntegerConstant(0),
        len: 2 as usize
    })
}
