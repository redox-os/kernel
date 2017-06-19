use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;

use super::{AmlInternalError, AmlExecutable, AmlValue, AmlNamespace, AmlNamespaceContents, get_namespace_string};
use super::pkglength::parse_pkg_length;
use super::namestring::parse_name_string;
use super::termlist::{parse_term_list, TermObj};
use super::dataobj::{parse_data_ref_obj, DataRefObj};

#[derive(Debug, Clone)]
pub enum NamespaceModifier {
    Name {
        name: String,
        data_ref_obj: DataRefObj
    },
    Scope {
        name: String,
        terms: Vec<TermObj>
    },
    Alias {
        source_name: String,
        alias_name: String
    },
    DeferredLoad(Vec<u8>)
}

impl AmlExecutable for NamespaceModifier {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue> {
        match *self {
            NamespaceModifier::Scope { name: ref name, terms: ref terms } => {
                let local_scope_string = get_namespace_string(scope, name.clone());
                namespace.push_subordinate_namespace(local_scope_string.clone());

                terms.execute(namespace, local_scope_string);
            },
            NamespaceModifier::Name { ref name, ref data_ref_obj } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                let dro = match data_ref_obj.execute(namespace, scope) {
                    Some(s) => s,
                    None => return None
                };

                namespace.push_to(local_scope_string, AmlNamespaceContents::Value(dro));
            },
            NamespaceModifier::Alias { ref source_name, ref alias_name } => {
                let local_scope_string = get_namespace_string(scope.clone(), source_name.clone());
                let local_alias_string = get_namespace_string(scope.clone(), alias_name.clone());

                namespace.push_to(local_scope_string, AmlNamespaceContents::Alias(local_alias_string));
            },
            _ => ()
        }

        None
    }
}

pub fn parse_namespace_modifier(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    parser_selector! {
        data,
        parse_alias_op,
        parse_scope_op,
        parse_name_op
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

fn parse_alias_op(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    parser_opcode!(data, 0x06);

    let (source_name, source_name_len) = parse_name_string(&data[1..])?;
    let (alias_name, alias_name_len) = parse_name_string(&data[1 + source_name_len..])?;

    Ok((NamespaceModifier::Alias {source_name, alias_name}, 1 + source_name_len + alias_name_len))
}

fn parse_name_op(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    parser_opcode!(data, 0x08);

    let (name, name_len) = parse_name_string(&data[1..])?;
    let (data_ref_obj, data_ref_obj_len) = parse_data_ref_obj(&data[1 + name_len..])?;

    Ok((NamespaceModifier::Name {name, data_ref_obj}, 1 + name_len + data_ref_obj_len))
}

fn parse_scope_op(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    parser_opcode!(data, 0x10);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (name, name_len) = match parse_name_string(&data[1 + pkg_length_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamespaceModifier::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()),
                       1 + pkg_length)),
        Err(e) => return Err(e)
    };
    let terms = match parse_term_list(&data[1 + pkg_length_len + name_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamespaceModifier::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()),
                       1 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((NamespaceModifier::Scope {name, terms}, pkg_length + 1))
}
