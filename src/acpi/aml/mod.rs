//! # AML
//! Code to parse and execute AML tables

use collections::vec::Vec;

use super::sdt::Sdt;

mod termlist;
mod namespacemodifier;
mod pkglength;
mod namestring;
mod namedobj;
mod dataobj;

use self::termlist::parse_term_list;

pub enum AmlError {
    AmlParseError
}

pub struct AmlTables;

pub enum AmlValue {
    NothingToSeeHere,
    MoveAlongCitizen
}

pub fn parse_aml_table(data: &[u8]) -> Result<Vec<u8>, AmlError> {
    parse_term_list(data)
}
