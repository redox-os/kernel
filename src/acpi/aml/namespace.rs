use collections::string::String;
use collections::vec::Vec;
use collections::boxed::Box;

use core::str::FromStr;

use super::namedobj::{ RegionSpace, FieldFlags, Method };

#[derive(Debug, Clone)]
pub struct AmlNamespace {
    name: String,
    contents: AmlNamespaceContents
}

#[derive(Debug, Clone)]
pub enum AmlNamespaceContents {
    Value(AmlValue),
    SubNamespace(Box<AmlNamespace>),
    Namespace(Vec<AmlNamespaceContents>),
    OpRegion {
        region: RegionSpace,
        offset: AmlValue,
        len: AmlValue
    },
    Field {
        op_region: String,
        flags: FieldFlags,
        offset: usize,
        length: usize
    }
}

#[derive(Debug, Clone)]
pub enum AmlValue {
    Uninitialized,
    Buffer,
    BufferField,
    DDBHandle,
    DebugObject,
    Device,
    Event,
    FieldUnit,
    Integer,
    IntegerConstant(u64),
    Method(Method),
    Mutex,
    ObjectReference,
    OperationRegion,
    Package(Vec<AmlValue>),
    String,
    PowerResource,
    Processor,
    RawDataBuffer,
    ThermalZone
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

impl AmlNamespace {
    pub fn new_namespace(name: &String) -> AmlNamespace {
        AmlNamespace {
            name: name.clone(),
            contents: AmlNamespaceContents::Namespace(vec!())
        }
    }

    pub fn find_str(&self, scope_str: &str) -> Option<AmlValue> {
        let scope_string = String::from_str(scope_str).unwrap();
        self.find(scope_string)
    }
    
    pub fn find(&self, scope_string: String) -> Option<AmlValue> {
        if scope_string.len() == 0 {
            match self.contents {
                AmlNamespaceContents::Value(ref v) => return Some(v.clone()),
                _ => return None
            }
        }
        
        let mut scope_string = scope_string.clone();
        
        if scope_string.starts_with("\\") {
            if self.name != "\\" {
                return None;
            }

            scope_string.remove(0);
        }

        if scope_string.starts_with(".") {
            scope_string.remove(0);
        }
        
        if scope_string.len() == 0 {
            match self.contents {
                AmlNamespaceContents::Value(ref v) => return Some(v.clone()),
                _ => return None
            }
        }

        let (current, nextset) = match scope_string.find(".") {
            Some(s) => {
                let (x, mut y) = scope_string.split_at(s);
                y = &y[1..];

                (String::from_str(x).unwrap(), String::from_str(y).unwrap())
            },
            None => if scope_string.len() <= 4 {
                (scope_string, String::from_str("").unwrap())
            } else {
                return None;
            }
        };

        match self.contents {
            AmlNamespaceContents::Namespace(ref namespace) => {
                // TODO: Remove this while loop here, there has to be a more elegant way
                let mut current_index = 0;
                while current_index < namespace.len() {
                    match namespace[current_index] {
                        AmlNamespaceContents::SubNamespace(ref ns) => if ns.name == current {
                            return ns.find(nextset);
                        },
                        _ => ()
                    }

                    current_index += 1;
                }
            },
            _ => ()
        }

        None
    }
    
    pub fn push(&mut self, val: AmlNamespaceContents) {
        match self.contents {
            AmlNamespaceContents::Namespace(ref mut v) => v.push(val),
            _ => () // TODO: Error this
        }
    }

    pub fn push_to(&mut self, scope_string: String, contents: AmlNamespaceContents) {
        if scope_string.len() == 0 {
            return;
        }
        
        let mut scope_string = scope_string.clone();
        
        if scope_string.starts_with("\\") {
            if self.name != "\\" {
                return;
                // TODO: Error this
            }

            scope_string.remove(0);
        }

        if scope_string.starts_with(".") {
            scope_string.remove(0);
        }
        
        if scope_string.len() == 0 {
            return;
        }

        let (current, nextset) = match scope_string.find(".") {
            Some(s) => {
                let (x, mut y) = scope_string.split_at(s);
                y = &y[1..];

                (String::from_str(x).unwrap(), String::from_str(y).unwrap())
            },
            None => if scope_string.len() <= 4 {
                (scope_string, String::from_str("").unwrap())
            } else {
                return;
            }
        };

        match self.contents {
            AmlNamespaceContents::Namespace(ref mut namespace) => {
                // TODO: Remove this while loop here, there has to be a more elegant way
                let mut current_index = 0;
                while current_index < namespace.len() {
                    match namespace[current_index] {
                        AmlNamespaceContents::SubNamespace(ref mut ns) => if ns.name == current {
                            ns.push_to(nextset, contents);
                            return;
                        },
                        _ => ()
                    }

                    current_index += 1;
                }
                
                let mut next = AmlNamespace {
                    name: current,
                    contents: contents
                };
                
                namespace.push(AmlNamespaceContents::SubNamespace(Box::new(next)));
            }
            _ => () // TODO: Error this
        }
    }

    pub fn push_subordinate_namespace(&mut self, scope_string: String) {
        self.push_to(scope_string, AmlNamespaceContents::Namespace(vec!()));
    }
}
