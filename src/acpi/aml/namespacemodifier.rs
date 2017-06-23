use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;

use super::{AmlInternalError, AmlExecutable, AmlValue, get_namespace_string};
use super::pkglength::parse_pkg_length;
use super::namestring::{parse_name_string, SuperName};
use super::termlist::{parse_term_list, TermObj};
use super::dataobj::{parse_data_ref_obj, DataRefObj};

pub fn parse_namespace_modifier(data: &[u8],
                                namespace: &mut BTreeMap<String, AmlValue>,
                                scope: String) -> ParseResult {
    parser_selector! {
        data, namespace, scope,
        parse_alias_op,
        parse_scope_op,
        parse_name_op
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

fn parse_alias_op(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    parser_opcode!(data, 0x06);

    let source_name = parse_name_string(&data[1..], namespace, scope)?;
    let alias_name = parse_name_string(&data[1 + source_name_len..], namespace, scope)?;
    
    let local_scope_string = get_namespace_string(scope.clone(), parser_verify_value!(source_name));
    let local_alias_string = get_namespace_string(scope.clone(), parser_verify_value!(alias_name));

    namespace.insert(local_scope_string, AmlValue::ObjectReference(
        SuperName::NameString(local_alias_string)));

    Ok(AmlParseType {
        val: None,
        len: 1 + source_name.len + alias_name.len
    })
}

fn parse_name_op(data: &[u8],
                 namespace: &mut BTreeMap<String, AmlValue>,
                 scope: String) -> ParseResult {
    parser_opcode!(data, 0x08);
    
    let name = parse_name_string(&data[1..], namespace, scope)?;
    let data_ref_obj = parse_data_ref_obj(&data[1 + name_len..], namespace, scope)?;
    
    let local_scope_string = get_namespace_string(scope.clone(), parser_verify_value!(name));

    namespace.insert(local_scope_string, parser_verify_value!(data_ref_obj));
    
    Ok(AmlParseType {
        val: None,
        len: 1 + name_len + data_ref_obj_len
    })
}

fn parse_scope_op(data: &[u8],
                  namespace: &mut BTreeMap<String, AmlValue>,
                  scope: String) -> ParseResult {
    parser_opcode!(data, 0x10);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let name = parse_name_string(&data[1 + pkg_length_len..], namespace, scope)?;
    
    let local_scope_string = get_namespace_string(scope, parser_verify_value!(name));
    parse_term_list(&data[1 + pkg_length_len + name_len..], namespace, local_scope_string)?;
    
    Ok(AmlParseType {
        val: None,
        len: 1 + pkg_length
    })
}
