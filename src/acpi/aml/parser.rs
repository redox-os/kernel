use collections::string::String;
use collections::btree_map::BTreeMap;
use collections::vec::Vec;

use super::namespace::{ AmlValue, ObjectReference };
use super::AmlError;

pub type ParseResult = Result<AmlParseType, AmlError>;
pub type AmlParseType = AmlParseTypeGeneric<AmlValue>;

pub struct AmlParseTypeGeneric<T> {
    pub val: T,
    pub len: usize
}

pub enum ExecutionState {
    EXECUTING,
    CONTINUE,
    BREAK,
    RETURN(AmlValue)
}

pub struct AmlExecutionContext {
    pub namespace: BTreeMap<String, AmlValue>,
    pub scope: String,
    pub local_vars: [AmlValue; 8],
    pub arg_vars: [AmlValue; 8],
    pub state: ExecutionState,
    pub namespace_delta: Vec<String>
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
                       AmlValue::Uninitialized],
            state: ExecutionState::EXECUTING,
            namespace_delta: vec!()
        }
    }

    pub fn add_to_namespace(&mut self, name: String, value: AmlValue) -> Result<(), AmlError> {
        if self.namespace.contains_key(&name) {
            return Err(AmlError::AmlValueError);
        }
            
        self.namespace_delta.push(name.clone());
        self.namespace.insert(name, value);

        Ok(())
    }

    pub fn clean_namespace(&mut self) {
        for k in &self.namespace_delta {
            self.namespace.remove(k);
        }
    }

    pub fn init_arg_vars(&mut self, parameters: Vec<AmlValue>) {
        if parameters.len() > 8 {
            return;
        }

        let mut cur = 0;
        while cur < parameters.len() {
            self.arg_vars[cur] = parameters[cur].clone();
            cur += 1;
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
