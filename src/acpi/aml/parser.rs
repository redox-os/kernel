use collections::string::String;
use collections::btree_map::BTreeMap;
use collections::vec::Vec;

use spin::RwLockWriteGuard;

use super::namespace::{ AmlValue, ObjectReference };
use super::AmlError;

use acpi::ACPI_TABLE;

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
    pub scope: String,
    pub local_vars: [AmlValue; 8],
    pub arg_vars: [AmlValue; 8],
    pub state: ExecutionState,
    pub namespace_delta: Vec<String>,
    pub ctx_id: u64
}

impl AmlExecutionContext {
    pub fn new(scope: String) -> AmlExecutionContext {
        let mut idptr = ACPI_TABLE.next_ctx.write();
        let id: u64 = *idptr;

        *idptr += 1;
        
        AmlExecutionContext {
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
            namespace_delta: vec!(),
            ctx_id: id
        }
    }

    pub fn add_to_namespace(&mut self, name: String, value: AmlValue) -> Result<(), AmlError> {
        let mut namespace = ACPI_TABLE.namespace.write();
        
        if let Some(ref mut namespace) = *namespace {
            if namespace.contains_key(&name) {
                return Err(AmlError::AmlValueError);
            }
            
            self.namespace_delta.push(name.clone());
            namespace.insert(name, value);

            Ok(())
        } else {
            Err(AmlError::AmlValueError)
        }
    }

    pub fn clean_namespace(&mut self) {
        let mut namespace = ACPI_TABLE.namespace.write();

        if let Some(ref mut namespace) = *namespace {
            for k in &self.namespace_delta {
                namespace.remove(k);
            }
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

    pub fn prelock(&mut self) -> RwLockWriteGuard<'static, Option<BTreeMap<String, AmlValue>>> {
        ACPI_TABLE.namespace.write()
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
