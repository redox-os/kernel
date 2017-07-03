use collections::string::String;
use collections::btree_map::BTreeMap;

use super::namespace::AmlValue;
use super::AmlError;

pub type ParseResult = Result<AmlParseType, AmlError>;
pub type AmlParseType = AmlParseTypeGeneric<AmlValue>;

pub struct AmlParseTypeGeneric<T> {
    pub val: T,
    pub len: usize
}

pub struct AmlExecutionContext<'a> {
    pub namespace: &'a mut BTreeMap<String, AmlValue>,
    pub scope: String
}
