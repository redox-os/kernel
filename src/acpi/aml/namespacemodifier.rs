use collections::vec::Vec;
use collections::string::String;

use super::AmlInternalError;
use super::pkglength::parse_pkg_length;
use super::namestring::parse_name_string;
use super::termlist::{parse_term_list, TermObj};
use super::dataobj::{parse_data_ref_obj, DataRefObj};

pub enum NamespaceModifier {
    Name {
        name: String,
        data_ref_obj: DataRefObj
    },
    Scope {
        name: String,
        terms: Vec<TermObj>
    },
    DeferredLoad(Vec<u8>)
}

pub fn parse_namespace_modifier(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    match parse_scope_op(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_name_op(data) {
        Ok(res) => Ok(res),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }
}

fn parse_name_op(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    if data[0] != 0x08 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (name, name_len) = parse_name_string(&data[1..])?;
    let (data_ref_obj, data_ref_obj_len) = parse_data_ref_obj(&data[1 + name_len..])?;
    
    Ok((NamespaceModifier::Name {name, data_ref_obj}, 1 + name_len + data_ref_obj_len))
}

fn parse_scope_op(data: &[u8]) -> Result<(NamespaceModifier, usize), AmlInternalError> {
    if data[0] != 0x10 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (name, name_len) = match parse_name_string(&data[1 + pkg_length_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamespaceModifier::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()),
                       1 + pkg_length))
    };
    let terms = match parse_term_list(&data[1 + pkg_length_len + name_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamespaceModifier::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()),
                       1 + pkg_length))
    };

    Ok((NamespaceModifier::Scope {name, terms}, pkg_length + 1))
}
