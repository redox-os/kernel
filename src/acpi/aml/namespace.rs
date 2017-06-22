use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use collections::btree_map::BTreeMap;

use core::str::FromStr;

use super::namedobj::{ RegionSpace, FieldFlags, Method };
use super::termlist::Object;
use super::namestring::SuperName;

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
pub enum AmlValue {
    Uninitialized,
    Buffer,
    BufferField {
        source_buf: Box<AmlValue>,
        index: Box<AmlValue>,
        length: Box<AmlValue>
    },
    DDBHandle,
    DebugObject,
    Device(BTreeMap<String, AmlValue>),
    Event,
    FieldUnit {
        selector: FieldSelector,
        flags: FieldFlags,
        offset: usize,
        length: usize
    },
    Integer,
    IntegerConstant(u64),
    Method(Method),
    Mutex(u8),
    ObjectReference(SuperName),
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
    RawDataBuffer,
    ThermalZone(BTreeMap<String, AmlValue>)
}

impl AmlValue {
    pub fn get_as_package(&self) -> Option<Vec<AmlValue>> {
        match *self {
            AmlValue::Package(ref p) => Some(p.clone()),
            _ => None
        }
    }

    pub fn get_as_integer(&self) -> Option<u64> {
        match *self {
            AmlValue::IntegerConstant(ref i) => Some(i.clone()),
            _ => None
        }
    }
}

pub fn get_namespace_string(current: String, modifier: String) -> String {
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
    namespace.push('.');
    namespace + &modifier
}
