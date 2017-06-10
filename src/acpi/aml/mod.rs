//! # AML
//! Code to parse and execute AML tables

use collections::vec::Vec;

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

// TODO: make private
#[derive(Debug)]
pub enum AmlInternalError {
    AmlParseError(&'static str),
    AmlInvalidOpCode,
    AmlDeferredLoad
}

pub enum AmlError {
    AmlParseError(&'static str)
}

pub struct AmlTables;

pub enum AmlValue {
    NothingToSeeHere,
    MoveAlongCitizen
}

pub fn parse_aml_table(data: &[u8]) -> Result<Vec<TermObj>, AmlError> {
    match parse_term_list(data) {
        Ok(res) => Ok(res),
        Err(AmlInternalError::AmlParseError(s)) => Err(AmlError::AmlParseError(s)),
        Err(AmlInternalError::AmlInvalidOpCode) => Err(AmlError::AmlParseError("Unable to match opcode")),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlError::AmlParseError("Deferred load reached top level"))
    }
}
