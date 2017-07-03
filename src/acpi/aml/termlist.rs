use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;

use super::AmlError;
use super::parser::{ AmlParseType, ParseResult, AmlParseTypeGeneric, AmlExecutionContext };
use super::namespace::{AmlValue, ObjectReference, FieldSelector, get_namespace_string};
use super::namespacemodifier::parse_namespace_modifier;
use super::namedobj::parse_named_obj;
use super::dataobj::{parse_data_obj, parse_arg_obj, parse_local_obj};
use super::type1opcode::parse_type1_opcode;
use super::type2opcode::parse_type2_opcode;
use super::namestring::parse_name_string;

pub fn parse_term_list(data: &[u8],
                       ctx: &mut AmlExecutionContext) -> ParseResult {
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let res = parse_term_obj(&data[current_offset..], ctx)?;
        current_offset += res.len;
    }

    Ok(AmlParseType {
        val: AmlValue::None,
        len: data.len()
    })
}

pub fn parse_term_arg(data: &[u8],
                      ctx: &mut AmlExecutionContext) -> ParseResult {
    parser_selector! {
        data, ctx,
        parse_local_obj,
        parse_data_obj,
        parse_arg_obj,
        parse_type2_opcode
    };

    Err(AmlError::AmlInvalidOpCode)
}

pub fn parse_object_list(data: &[u8],
                         ctx: &mut AmlExecutionContext) -> ParseResult {
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let res = parse_object(&data[current_offset..], ctx)?;
        current_offset += res.len;
    }

    Ok(AmlParseType {
        val: AmlValue::None,
        len: data.len()
    })
}

fn parse_object(data: &[u8],
                ctx: &mut AmlExecutionContext) -> ParseResult {
    parser_selector! {
        data, ctx,
        parse_namespace_modifier,
        parse_named_obj
    };

    Err(AmlError::AmlInvalidOpCode)
}

pub fn parse_method_invocation(data: &[u8],
                               ctx: &mut AmlExecutionContext) -> ParseResult {
    // TODO: Check if method exists in namespace
    // TODO: If so, parse appropriate number of parameters
    // TODO: If not, add deferred load to ctx
    let name = parse_name_string(data, ctx)?;
    Err(AmlError::AmlDeferredLoad)
}

fn parse_term_obj(data: &[u8],
                  ctx: &mut AmlExecutionContext) -> ParseResult {
    parser_selector! {
        data, ctx,
        parse_namespace_modifier,
        parse_named_obj,
        parse_type1_opcode,
        parse_type2_opcode
    };

    Err(AmlError::AmlInvalidOpCode)
}
