use alloc::boxed::Box;
use collections::string::String;
use collections::string::ToString;
use collections::vec::Vec;

use core::fmt::{Debug, Formatter, Error};

use super::termlist::parse_term_list;
use super::namedobj::{ RegionSpace, FieldFlags };
use super::parser::{AmlExecutionContext, ExecutionState};
use super::AmlError;

#[derive(Clone)]
pub enum FieldSelector {
    Region(String),
    Bank {
        region: String,
        bank_selector: Box<AmlValue>
    },
    Index {
        index_selector: String,
        data_selector: String
    }
}

#[derive(Clone)]
pub enum ObjectReference {
    ArgObj(u8),
    LocalObj(u8),
    NamedObj(String),
    Object(Box<AmlValue>),
    Index(Box<AmlValue>, Box<AmlValue>)
}

#[derive(Clone)]
pub struct Method {
    pub arg_count: u8,
    pub serialized: bool,
    pub sync_level: u8,
    pub term_list: Vec<u8>
}

pub struct Accessor {
    pub read: fn(usize) -> u64,
    pub write: fn(usize, u64)
}

impl Clone for Accessor {
    fn clone(&self) -> Accessor {
        Accessor {
            read: (*self).read,
            write: (*self).write
        }
    }
}

#[derive(Clone)]
pub enum AmlValue {
    None,
    Uninitialized,
    Buffer(Vec<u8>),
    BufferField {
        source_buf: Box<AmlValue>,
        index: Box<AmlValue>,
        length: Box<AmlValue>
    },
    DDBHandle(Vec<String>),
    DebugObject,
    Device(Vec<String>),
    Event(u64),
    FieldUnit {
        selector: FieldSelector,
        connection: Box<AmlValue>,
        flags: FieldFlags,
        offset: usize,
        length: usize
    },
    Integer(u64),
    IntegerConstant(u64),
    Method(Method),
    Mutex((u8, Option<u64>)),
    ObjectReference(ObjectReference),
    OperationRegion {
        region: RegionSpace,
        offset: Box<AmlValue>,
        len: Box<AmlValue>,
        accessor: Accessor,
        accessed_by: Option<u64>
    },
    Package(Vec<AmlValue>),
    String(String),
    PowerResource {
        system_level: u8,
        resource_order: u16,
        obj_list: Vec<String>
    },
    Processor {
        proc_id: u8,
        p_blk: Option<u32>,
        obj_list: Vec<String>
    },
    RawDataBuffer(Vec<u8>),
    ThermalZone(Vec<String>)
}

impl Debug for AmlValue {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> { Ok(()) }
}

impl AmlValue {
    pub fn get_as_event(&self) -> Result<u64, AmlError> {
        match *self {
            AmlValue::Event(ref e) => Ok(e.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }

    pub fn get_as_ddb_handle(&self) -> Result<Vec<String>, AmlError> {
        match *self {
            AmlValue::DDBHandle(ref v) => Ok(v.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }
    
    pub fn get_as_string(&self) -> Result<String, AmlError> {
        match *self {
            AmlValue::String(ref s) => Ok(s.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }

    pub fn get_as_buffer(&self) -> Result<Vec<u8>, AmlError> {
        match *self {
            AmlValue::Buffer(ref b) => Ok(b.clone()),
            AmlValue::Integer(ref i) => {
                let mut v: Vec<u8> = vec!();
                let mut i = i.clone();

                while i != 0 {
                    v.push((i & 0xFF) as u8);
                    i >>= 8;
                }

                while v.len() < 8 {
                    v.push(0);
                }

                Ok(v)
            },
            _ => Err(AmlError::AmlValueError)
        }
    }
    
    pub fn get_as_package(&self) -> Result<Vec<AmlValue>, AmlError> {
        match *self {
            AmlValue::Package(ref p) => Ok(p.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }

    pub fn get_as_integer(&self) -> Result<u64, AmlError> {
        match *self {
            AmlValue::IntegerConstant(ref i) => Ok(i.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }

    pub fn get_as_method(&self) -> Result<Method, AmlError> {
        match *self {
            AmlValue::Method(ref m) => Ok(m.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }
}

impl Method {
    pub fn execute(&self, scope: String, parameters: Vec<AmlValue>) -> AmlValue {
        let mut ctx = AmlExecutionContext::new(scope);
        ctx.init_arg_vars(parameters);

        parse_term_list(&self.term_list[..], &mut ctx);
        ctx.clean_namespace();

        match ctx.state {
            ExecutionState::RETURN(v) => v,
            _ => AmlValue::IntegerConstant(0)
        }
    }
}

pub fn get_namespace_string(current: String, modifier_v: AmlValue) -> Result<String, AmlError> {
    let mut modifier = modifier_v.get_as_string()?;
    
    if current.len() == 0 {
        return Ok(modifier);
    }

    if modifier.len() == 0 {
        return Ok(current);
    }
    
    if modifier.starts_with("\\") {
        return Ok(modifier);
    }

    let mut namespace = current.clone();

    if modifier.starts_with("^") {
        while modifier.starts_with("^") {
            modifier = modifier[1..].to_string();

            if namespace.ends_with("\\") {
                return Err(AmlError::AmlValueError);
            }

            loop {
                if namespace.ends_with(".") {
                    namespace.pop();
                    break;
                }

                if namespace.pop() == None {
                    return Err(AmlError::AmlValueError);
                }
            }
        }
    }

    if !namespace.ends_with("\\") {
        namespace.push('.');
    }
    
    Ok(namespace + &modifier)
}
