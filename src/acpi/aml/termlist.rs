use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;

use super::{AmlInternalError, AmlExecutable, AmlValue, get_namespace_string};
use super::namespacemodifier::{parse_namespace_modifier, NamespaceModifier};
use super::namedobj::{parse_named_obj, NamedObj};
use super::dataobj::{parse_data_obj, parse_arg_obj, parse_local_obj, DataObj, ArgObj, LocalObj};
use super::type1opcode::{parse_type1_opcode, Type1OpCode};
use super::type2opcode::{parse_type2_opcode, Type2OpCode};
use super::namestring::parse_name_string;

#[derive(Debug, Clone)]
pub enum TermArg {
    LocalObj(Box<LocalObj>),
    DataObj(Box<DataObj>),
    ArgObj(Box<ArgObj>),
    Type2Opcode(Box<Type2OpCode>)
}

#[derive(Debug, Clone)]
pub enum TermObj {
    NamespaceModifier(Box<NamespaceModifier>),
    NamedObj(Box<NamedObj>),
    Type1Opcode(Box<Type1OpCode>),
    Type2Opcode(Box<Type2OpCode>)
}

#[derive(Debug, Clone)]
pub enum Object {
    NamespaceModifier(Box<NamespaceModifier>),
    NamedObj(Box<NamedObj>)
}

#[derive(Debug, Clone)]
pub struct MethodInvocation {

}

impl AmlExecutable for Vec<Object> {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue> {
        for term in self {
            term.execute(namespace, scope.clone());
        }

        None
    }
}

impl AmlExecutable for Object {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue> {
        match *self {
            Object::NamespaceModifier(ref d) => d.execute(namespace, scope),
            Object::NamedObj(ref d) => d.execute(namespace, scope)
        }
    }
}

impl AmlExecutable for Vec<TermObj> {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue> {
        for term in self {
            term.execute(namespace, scope.clone());
        }

        None
    }
}

impl AmlExecutable for TermArg {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue> {
        match *self {
            TermArg::LocalObj(ref l) => Some(AmlValue::Uninitialized),
            TermArg::DataObj(ref d) => d.execute(namespace, scope),
            TermArg::ArgObj(ref a) => Some(AmlValue::Uninitialized),
            TermArg::Type2Opcode(ref o) => Some(AmlValue::Uninitialized)
        }
    }
}

impl AmlExecutable for TermObj {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue> {
        match *self {
            TermObj::NamespaceModifier(ref res) => res.execute(namespace, scope.clone()),
            TermObj::NamedObj(ref res) => res.execute(namespace, scope.clone()),
            TermObj::Type1Opcode(ref res) => res.execute(namespace, scope.clone()),
            TermObj::Type2Opcode(ref res) => res.execute(namespace, scope.clone())
        }
    }
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
    parser_selector! {
        data,
        parser_wrap!(TermArg::LocalObj, parser_wrap!(Box::new, parse_local_obj)),
        parser_wrap!(TermArg::DataObj, parser_wrap!(Box::new, parse_data_obj)),
        parser_wrap!(TermArg::ArgObj, parser_wrap!(Box::new, parse_arg_obj)),
        parser_wrap!(TermArg::Type2Opcode, parser_wrap!(Box::new, parse_type2_opcode))
    };

    Err(AmlInternalError::AmlInvalidOpCode)
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
    parser_selector! {
        data,
        parser_wrap!(Object::NamespaceModifier, parser_wrap!(Box::new, parse_namespace_modifier)),
        parser_wrap!(Object::NamedObj, parser_wrap!(Box::new, parse_named_obj))
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_method_invocation(data: &[u8]) -> Result<(MethodInvocation, usize), AmlInternalError> {
    let (name, name_len) = parse_name_string(data)?;
    Err(AmlInternalError::AmlDeferredLoad)
}

fn parse_term_obj(data: &[u8]) -> Result<(TermObj, usize), AmlInternalError> {
    parser_selector! {
        data,
        parser_wrap!(TermObj::NamespaceModifier, parser_wrap!(Box::new, parse_namespace_modifier)),
        parser_wrap!(TermObj::NamedObj, parser_wrap!(Box::new, parse_named_obj)),
        parser_wrap!(TermObj::Type1Opcode, parser_wrap!(Box::new, parse_type1_opcode)),
        parser_wrap!(TermObj::Type2Opcode, parser_wrap!(Box::new, parse_type2_opcode))
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}
