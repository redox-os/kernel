use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;

use core::str::FromStr;

use super::termlist::parse_term_list;
use super::namedobj::{ RegionSpace, FieldFlags };
use super::parser::AmlExecutionContext;
use super::AmlError;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub enum ObjectReference {
    ArgObj(u8),
    LocalObj(u8),
    NamedObj(String),
    Object(Box<AmlValue>)
}

#[derive(Debug, Clone)]
pub struct Method {
    pub arg_count: u8,
    pub serialized: bool,
    pub sync_level: u8,
    pub term_list: Vec<u8>
}

#[derive(Debug, Clone)]
pub enum AmlValue {
    None,
    Uninitialized,
    Buffer(Vec<u8>),
    BufferField {
        source_buf: Box<AmlValue>,
        index: Box<AmlValue>,
        length: Box<AmlValue>
    },
    DDBHandle(u32), // Index into the XSDT
    DebugObject,
    Device(BTreeMap<String, AmlValue>),
    Event,
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
    Mutex(u8),
    ObjectReference(ObjectReference),
    OperationRegion {
        region: RegionSpace,
        offset: Box<AmlValue>,
        len: Box<AmlValue>
    },
    Package(Vec<AmlValue>),
    String(String),
    PowerResource {
        system_level: u8,
        resource_order: u16,
        obj_list: BTreeMap<String, AmlValue>
    },
    Processor {
        proc_id: u8,
        p_blk: Option<u32>,
        obj_list: BTreeMap<String, AmlValue>
    },
    RawDataBuffer(Vec<u8>),
    ThermalZone(BTreeMap<String, AmlValue>)
}

impl AmlValue {
    pub fn get_as_string(&self) -> Result<String, AmlError> {
        match *self {
            AmlValue::String(ref s) => Ok(s.clone()),
            _ => Err(AmlError::AmlValueError)
        }
    }

    pub fn get_as_buffer(&self) -> Result<Vec<u8>, AmlError> {
        match *self {
            AmlValue::Buffer(ref b) => Ok(b.clone()),
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

        AmlValue::None
    }
}

pub fn get_namespace_string(current: String, modifier_v: AmlValue) -> String {
    // TODO: Type error if modifier not string
    let modifier = if let Ok(s) = modifier_v.get_as_string() {
        s
    } else {
        return current;
    };
    
    if current.len() == 0 {
        return modifier;
    }

    if modifier.len() == 0 {
        return current;
    }
    
    if modifier.starts_with("\\") {
        return modifier;
    }

    if modifier.starts_with("^") {
        // TODO
    }

    let mut namespace = current.clone();

    if !namespace.ends_with("\\") {
        namespace.push('.');
    }
    
    namespace + &modifier
}
