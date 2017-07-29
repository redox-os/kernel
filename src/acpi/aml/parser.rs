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
    pub ctx_id: u64,
    pub sync_level: u8
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
            ctx_id: id,
            sync_level: 0
        }
    }
    
    pub fn release_mutex(&mut self, mutex_ptr: AmlValue) -> Result<(), AmlError> {
        let id = self.ctx_id;
        
        let mut namespace_ptr = self.prelock();
        let mut namespace = match *namespace_ptr {
            Some(ref mut n) => n,
            None => return Err(AmlError::AmlHardFatal)
        };
        
        let mutex_idx = match mutex_ptr {
            AmlValue::String(ref s) => s.clone(),
            AmlValue::ObjectReference(ref o) => match *o {
                ObjectReference::Object(ref s) => s.clone(),
                _ => return Err(AmlError::AmlValueError)
            },
            _ => return Err(AmlError::AmlValueError)
        };

        let mutex = match namespace.get(&mutex_idx) {
            Some(s) => s.clone(),
            None => return Err(AmlError::AmlValueError)
        };
        
        match mutex {
            AmlValue::Mutex((sync_level, owner)) => {
                if let Some(o) = owner {
                    if o == id {
                        if sync_level == self.sync_level {
                            namespace.insert(mutex_idx, AmlValue::Mutex((sync_level, None)));
                            return Ok(());
                        } else {
                            return Err(AmlError::AmlValueError);
                        }
                    } else {
                        return Err(AmlError::AmlHardFatal);
                    }
                }
            },
            AmlValue::OperationRegion(ref region) => {
                if let Some(o) = region.accessed_by {
                    if o == id {
                        let mut new_region = region.clone();
                        new_region.accessed_by = None;
                        
                        namespace.insert(mutex_idx, AmlValue::OperationRegion(new_region));
                        return Ok(());
                    } else {
                        return Err(AmlError::AmlHardFatal);
                    }
                }
            },
            _ => return Err(AmlError::AmlValueError)
        }

        Ok(())
    }

    pub fn acquire_mutex(&mut self, mutex_ptr: AmlValue, timeout: u16) -> Result<bool, AmlError> {
        let id = self.ctx_id;
        
        
        let mut namespace_ptr = self.prelock();
        let mut namespace = match *namespace_ptr {
            Some(ref mut n) => n,
            None => return Err(AmlError::AmlHardFatal)
        };
        let mutex_idx = match mutex_ptr {
            AmlValue::String(ref s) => s.clone(),
            AmlValue::ObjectReference(ref o) => match *o {
                ObjectReference::Object(ref s) => s.clone(),
                _ => return Err(AmlError::AmlValueError)
            },
            _ => return Err(AmlError::AmlValueError)
        };

        let mutex = match namespace.get(&mutex_idx) {
            Some(s) => s.clone(),
            None => return Err(AmlError::AmlValueError)
        };
        
        match mutex {
            AmlValue::Mutex((sync_level, owner)) => {
                if owner == None {
                    if sync_level < self.sync_level {
                        return Err(AmlError::AmlValueError);
                    }
                    
                    namespace.insert(mutex_idx, AmlValue::Mutex((sync_level, Some(id))));
                    self.sync_level = sync_level;
                    
                    return Ok(true);
                }
            },
            AmlValue::OperationRegion(ref o) => {
                if o.accessed_by == None {
                    let mut new_region = o.clone();
                    new_region.accessed_by = Some(id);

                    namespace.insert(mutex_idx, AmlValue::OperationRegion(new_region));
                    return Ok(true);
                }
            },
            _ => return Err(AmlError::AmlValueError)
        }

        Ok(false)
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
                ObjectReference::ArgObj(_) => (),
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
