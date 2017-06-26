//! # AML
//! Code to parse and execute AML tables

use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use core::fmt::Debug;
use core::str::FromStr;

use super::sdt::Sdt;

#[macro_use]
mod parsermacros;

mod namespace;
mod termlist;
mod namespacemodifier;
mod pkglength;
mod namestring;
mod namedobj;
mod dataobj;
mod type1opcode;
mod type2opcode;

use self::termlist::{parse_term_list, TermObj};
pub use self::namespace::{AmlNamespace, AmlValue};
use self::namespace::AmlNamespaceContents;

// TODO: This should be able to take parameters, and may also return multiple values
pub trait AmlExecutable {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue>;
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

pub fn get_namespace_string(current: String, modifier: String) -> String {
    if modifier.starts_with("\\") {
        return modifier;
    }

    if modifier.starts_with("^") {
        // TODO
    }

    let mut namespace = current.clone();
    namespace.push('.');
    namespace + &modifier
}

pub fn parse_aml_table(sdt: &'static Sdt) -> Result<AmlNamespace, AmlError> {
    let data = sdt.data();

    let term_list = match parse_term_list(data) {
        Ok(res) => res,
        Err(AmlInternalError::AmlParseError(s)) => return Err(AmlError::AmlParseError(s)),
        Err(AmlInternalError::AmlInvalidOpCode) => return Err(AmlError::AmlParseError("Unable to match opcode")),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlError::AmlParseError("Deferred load reached top level"))
    };

    let global_namespace_specifier = String::from_str("\\").unwrap();
    // Unwrap is fine here. I mean come on, if this goes wrong you've got bigger problems than AML
    // not loading...

    let mut global_namespace = AmlNamespace::new_namespace(&global_namespace_specifier);
    term_list.execute(&mut global_namespace, global_namespace_specifier.clone());

    Ok(global_namespace)
}

pub fn is_aml_table(sdt: &'static Sdt) -> bool {
    if &sdt.signature == b"DSDT" {//|| &sdt.signature == b"SSDT" {
        true
    } else {
        false
    }
}
