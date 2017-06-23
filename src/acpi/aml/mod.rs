//! # AML
//! Code to parse and execute AML tables

use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;
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
mod parser;

use self::parser::{ParseResult, AmlInternalError};
use self::termlist::{parse_term_list, TermObj};
pub use self::namespace::{get_namespace_string, AmlValue};

pub trait AmlExecutable {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue>;
}

pub enum AmlError {
    AmlParseError(&'static str)
}

pub fn parse_aml_table(sdt: &'static Sdt) -> Result<BTreeMap<String, AmlValue>, AmlError> {
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

    let mut global_namespace = BTreeMap::new();
    term_list.execute(&mut global_namespace, global_namespace_specifier.clone());

    Ok(global_namespace)
}

pub fn is_aml_table(sdt: &'static Sdt) -> bool {
    if &sdt.signature == b"DSDT" || &sdt.signature == b"SSDT" {
        true
    } else {
        false
    }
}
