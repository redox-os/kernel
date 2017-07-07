use collections::string::String;
use collections::btree_map::BTreeMap;

use super::namespace::{ AmlValue, ObjectReference };
use super::AmlError;

pub type ParseResult = Result<AmlParseType, AmlError>;
pub type AmlParseType = AmlParseTypeGeneric<AmlValue>;

pub struct AmlParseTypeGeneric<T> {
    pub val: T,
    pub len: usize
}

pub struct AmlExecutionContext {
    pub namespace: BTreeMap<String, AmlValue>,
    pub scope: String,
    pub local_vars: [AmlValue; 8],
    pub arg_vars: [AmlValue; 8]
}

impl AmlExecutionContext {
    pub fn new(scope: String) -> AmlExecutionContext {
        AmlExecutionContext {
            namespace: BTreeMap::new(),
            scope: scope,
            local_vars: [AmlValue::Uninitialized,
                         AmlValue::Uninitialized,
                         AmlValue::Uninitialized,
                         AmlValue::Uninitialized,
                         AmlValue::Uninitialized,
                         AmlValue::Uninitialized,
                         AmlValue::Uninitialized,
                         AmlValue::Uninitialized],
            arg_vars: [AmlValue::Uninitialized,
                       AmlValue::Uninitialized,
                       AmlValue::Uninitialized,
                       AmlValue::Uninitialized,
                       AmlValue::Uninitialized,
                       AmlValue::Uninitialized,
                       AmlValue::Uninitialized,
                       AmlValue::Uninitialized]
        }
    }

    pub fn modify(&mut self, name: AmlValue, value: AmlValue) {
        // TODO: throw errors
        // TODO: return DRO
        match name {
            AmlValue::None => (),
            AmlValue::ObjectReference(r) => match r {
                ObjectReference::ArgObj(i) => (),
                ObjectReference::LocalObj(i) => self.local_vars[i as usize] = value,
                _ => ()
            },
            _ => ()
        }
    }

    pub fn get(&self, name: AmlValue) -> AmlValue {
        match name {
            AmlValue::None => AmlValue::None,
            AmlValue::ObjectReference(r) => match r {
                ObjectReference::ArgObj(i) => self.arg_vars[i as usize].clone(),
                ObjectReference::LocalObj(i) => self.local_vars[i as usize].clone(),
                _ => AmlValue::None
            },
            _ => AmlValue::None
        }
    }
}
