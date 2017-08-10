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

    pub fn wait_for_event(&mut self, event_ptr: AmlValue) -> Result<bool, AmlError> {
        let mut namespace_ptr = self.prelock();
        let mut namespace = match *namespace_ptr {
            Some(ref mut n) => n,
            None => return Err(AmlError::AmlHardFatal)
        };
        
        let mutex_idx = match event_ptr {
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
            AmlValue::Event(count) => {
                if count > 0 {
                    namespace.insert(mutex_idx, AmlValue::Event(count - 1));
                    return Ok(true);
                }
            },
            _ => return Err(AmlError::AmlValueError)
        }

        Ok(false)
    }

    pub fn signal_event(&mut self, event_ptr: AmlValue) -> Result<(), AmlError> {
        let mut namespace_ptr = self.prelock();
        let mut namespace = match *namespace_ptr {
            Some(ref mut n) => n,
            None => return Err(AmlError::AmlHardFatal)
        };

        
        let mutex_idx = match event_ptr {
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
            AmlValue::Event(count) => {
                namespace.insert(mutex_idx, AmlValue::Event(count + 1));
                return Ok(());
            },
            _ => return Err(AmlError::AmlValueError)
        }

        Ok(())
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

    pub fn acquire_mutex(&mut self, mutex_ptr: AmlValue) -> Result<bool, AmlError> {
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

    fn modify_local_obj(&mut self, local: usize, value: AmlValue) -> Result<(), AmlError> {
        self.local_vars[local] = value;
        Ok(())
    }

    fn modify_object(&mut self, name: String, value: AmlValue) -> Result<(), AmlError> {
        if let Some(ref mut namespace) = *ACPI_TABLE.namespace.write() {
            namespace.insert(name, value);
            Ok(())
        } else {
            Err(AmlError::AmlHardFatal)
        }
    }

    fn modify_index_final(&mut self, name: String, value: AmlValue, indices: Vec<u64>) -> Result<(), AmlError> {
        if let Some(ref mut namespace) = *ACPI_TABLE.namespace.write() {
            let obj = if let Some(s) = namespace.get(&name) {
                s.clone()
            } else {
                return Err(AmlError::AmlValueError);
            };
            
            match obj {
                AmlValue::String(ref string) => {
                    if indices.len() != 1 {
                        return Err(AmlError::AmlValueError);
                    }
                    
                    let mut bytes = string.clone().into_bytes();
                    bytes[indices[0] as usize] = value.get_as_integer()? as u8;
                    
                    let string = String::from_utf8(bytes).unwrap();
                    namespace.insert(name, AmlValue::String(string));
                },
                AmlValue::Buffer(ref b) => {
                    if indices.len() != 1 {
                        return Err(AmlError::AmlValueError);
                    }
                    
                    let mut b = b.clone();
                    b[indices[0] as usize] = value.get_as_integer()? as u8;
                    
                    namespace.insert(name, AmlValue::Buffer(b));
                },
                AmlValue::Package(ref p) => {
                    // TODO: Nested references need to be handled here
                    if indices.len() < 0 {
                        return Err(AmlError::AmlValueError);
                    }
                    
                    let mut p = p.clone();
//                    let ref mut current = p;
                    
                    p[indices[0] as usize] = value;
                    
                    namespace.insert(name, AmlValue::Package(p));
                },
                _ => return Err(AmlError::AmlValueError)
            }
        }

        Ok(())
    }

    pub fn modify(&mut self, name: AmlValue, value: AmlValue) -> Result<(), AmlError> {
        match name {
            AmlValue::ObjectReference(r) => match r {
                ObjectReference::ArgObj(_) => Err(AmlError::AmlValueError),
                ObjectReference::LocalObj(i) => self.modify_local_obj(i as usize, value),
                ObjectReference::Object(s) => self.modify_object(s, value),
                ObjectReference::Index(c, v) => {
                    let idx = v.get_as_integer()?;
                    match *c {
                        AmlValue::ObjectReference(r) => match r {
                            ObjectReference::Object(s) => self.modify_index_final(s, value, vec!(idx)),
                            _ => Err(AmlError::AmlValueError)
                        },
                        _ => Err(AmlError::AmlValueError)
                    }
                }
            },
            AmlValue::String(s) => self.modify_object(s, value),
            _ => Err(AmlError::AmlValueError)
        }
    }

    pub fn get(&self, name: AmlValue) -> Result<AmlValue, AmlError> {
        Ok(match name {
            AmlValue::ObjectReference(r) => match r {
                ObjectReference::ArgObj(i) => self.arg_vars[i as usize].clone(),
                ObjectReference::LocalObj(i) => self.local_vars[i as usize].clone(),
                ObjectReference::Object(ref s) => if let Some(ref namespace) = *ACPI_TABLE.namespace.read() {
                    if let Some(o) = namespace.get(s) {
                        o.clone()
                    } else {
                        AmlValue::None
                    }
                } else { AmlValue::None },
                ObjectReference::Index(c, v) => if let Some(ref mut namespace) = *ACPI_TABLE.namespace.write() {
                    let idx = v.get_as_integer()? as usize;
                    match *c {
                        AmlValue::Package(p) => p[idx].clone(),
                        _ => AmlValue::None
                    }
                } else {
                    AmlValue::None
                }
            },
            AmlValue::String(ref s) => if let Some(ref namespace) = *ACPI_TABLE.namespace.read() {
                if let Some(o) = namespace.get(s) {
                    o.clone()
                } else {
                    AmlValue::None
                }
            } else { AmlValue::None },
            _ => AmlValue::None
        })
    }
}
