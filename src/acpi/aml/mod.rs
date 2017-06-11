//! # AML
//! Code to parse and execute AML tables

use collections::vec::Vec;
use collections::string::String;
use collections::boxed::Box;
use core::fmt::Debug;
use core::str::FromStr;

use super::sdt::Sdt;

#[macro_use]
mod parsermacros;

mod termlist;
mod namespacemodifier;
mod pkglength;
mod namestring;
mod namedobj;
mod dataobj;
mod type1opcode;
mod type2opcode;

use self::termlist::{parse_term_list, TermObj};

// TODO: This should be able to take parameters, and may also return multiple values
pub trait AmlExecutable {
    fn execute(&self, namespace: &mut AmlTables, scope: String) -> Option<Box<AmlScopeVal>>;
}

// TODO: make private
pub enum AmlInternalError {
    AmlParseError(&'static str),
    AmlInvalidOpCode,
    AmlDeferredLoad
}

pub enum AmlError {
    AmlParseError(&'static str)
}

pub trait AmlScopeVal: Debug { }

#[derive(Debug)]
pub struct AmlTables {
    name: String,
    contents: Vec<Box<AmlScopeVal>>
}

impl AmlTables {
    fn push(&mut self, val: Box<AmlScopeVal>) {
        self.contents.push(val);
    }
}

impl AmlScopeVal for AmlTables { }

#[derive(Debug)]
pub enum AmlValue {
    Uninitialized,
    Buffer,
    BufferField,
    DDBHandle,
    DebugObject,
    Device,
    Event,
    FieldUnit,
    Integer,
    IntegerConstant,
    Method,
    Mutex,
    ObjectReference,
    OperationRegion,
    Package,
    String,
    PowerResource,
    Processor,
    RawDataBuffer,
    ThermalZone
}

impl AmlScopeVal for AmlValue { }

pub fn parse_aml_table(data: &[u8]) -> Result<Vec<TermObj>, AmlError> {
    let term_list = match parse_term_list(data) {
        Ok(res) => res,
        Err(AmlInternalError::AmlParseError(s)) => return Err(AmlError::AmlParseError(s)),
        Err(AmlInternalError::AmlInvalidOpCode) => return Err(AmlError::AmlParseError("Unable to match opcode")),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlError::AmlParseError("Deferred load reached top level"))
    };

    let global_namespace_specifier = String::from_str("/").unwrap();
    // Unwrap is fine here. I mean come on, if this goes wrong you've got bigger problems than AML
    // not loading...

    let mut global_namespace = AmlTables {
        name: global_namespace_specifier.clone(),
        contents: vec!()
    };
    term_list.execute(&mut global_namespace, global_namespace_specifier.clone());

    println!("{:#?}", global_namespace);

    Ok(term_list)
}
