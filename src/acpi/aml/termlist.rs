use collections::vec::Vec;
use collections::boxed::Box;

use super::AmlInternalError;
use super::namespacemodifier::{parse_namespace_modifier, NamespaceModifier};
use super::namedobj::{parse_named_obj, NamedObj};
use super::dataobj::{parse_data_obj, parse_arg_obj, parse_local_obj, DataObj, ArgObj, LocalObj};
use super::type1opcode::{parse_type1_opcode, Type1OpCode};
use super::type2opcode::{parse_type2_opcode, Type2OpCode};
use super::namestring::parse_name_string;

#[derive(Debug)]
pub enum TermArg {
    LocalObj(Box<LocalObj>),
    DataObj(Box<DataObj>),
    ArgObj(Box<ArgObj>),
    Type2Opcode(Box<Type2OpCode>)
}

#[derive(Debug)]
pub enum TermObj {
    NamespaceModifier(Box<NamespaceModifier>),
    NamedObj(Box<NamedObj>),
    Type1Opcode(Box<Type1OpCode>),
    Type2Opcode(Box<Type2OpCode>)
}

#[derive(Debug)]
pub enum Object {
    NamespaceModifier(Box<NamespaceModifier>),
    NamedObj(Box<NamedObj>)
}

#[derive(Debug)]
pub struct MethodInvocation {

}

pub fn parse_term_list(data: &[u8]) -> Result<Vec<TermObj>, AmlInternalError> {
    let mut terms: Vec<TermObj> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let (res, len) = parse_term_obj(&data[current_offset..])?;
        terms.push(res);
        current_offset += len;
    }

    Ok(terms)
}

pub fn parse_term_arg(data: &[u8]) -> Result<(TermArg, usize), AmlInternalError> {
    match parse_local_obj(data) {
        Ok((res, size)) => return Ok((TermArg::LocalObj(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_data_obj(data) {
        Ok((res, size)) => return Ok((TermArg::DataObj(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_arg_obj(data) {
        Ok((res, size)) => return Ok((TermArg::ArgObj(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_type2_opcode(data) {
        Ok((res, size)) => return Ok((TermArg::Type2Opcode(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    Err(AmlInternalError::AmlParseError)
}

pub fn parse_object_list(data: &[u8]) -> Result<Vec<Object>, AmlInternalError> {
    let mut terms: Vec<Object> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let (res, len) = parse_object(&data[current_offset..])?;
        terms.push(res);
        current_offset += len;
    }
    
    Ok(terms)
}

fn parse_object(data: &[u8]) -> Result<(Object, usize), AmlInternalError> {
    match parse_namespace_modifier(data) {
        Ok((ns, size)) => return Ok((Object::NamespaceModifier(Box::new(ns)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_named_obj(data) {
        Ok((obj, size)) => Ok((Object::NamedObj(Box::new(obj)), size)),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }
}

pub fn parse_method_invocation(data: &[u8]) -> Result<(MethodInvocation, usize), AmlInternalError> {
    let (name, name_len) = parse_name_string(data)?;
    Err(AmlInternalError::AmlDeferredLoad)
}

fn parse_term_obj(data: &[u8]) -> Result<(TermObj, usize), AmlInternalError> {
    match parse_namespace_modifier(data) {
        Ok((res, size)) => return Ok((TermObj::NamespaceModifier(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_named_obj(data) {
        Ok((res, size)) => return Ok((TermObj::NamedObj(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_type1_opcode(data) {
        Ok((res, size)) => return Ok((TermObj::Type1Opcode(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_type2_opcode(data) {
        Ok((res, size)) => return Ok((TermObj::Type2Opcode(Box::new(res)), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    Err(AmlInternalError::AmlParseError)
}
