use collections::vec::Vec;
use collections::string::String;

use super::{AmlInternalError, AmlExecutable, AmlValue, AmlNamespace, get_namespace_string};

use super::type2opcode::{parse_def_buffer, parse_def_package, parse_def_var_package,
                         DefBuffer, DefPackage, DefVarPackage};
use super::termlist::{parse_term_arg, TermArg};
use super::namestring::{parse_super_name, SuperName};

#[derive(Debug, Clone)]
pub enum DataObj {
    ComputationalData(ComputationalData),
    DefPackage(DefPackage),
    DefVarPackage(DefVarPackage)
}

#[derive(Debug, Clone)]
pub enum DataRefObj {
    DataObj(DataObj),
    ObjectReference(TermArg),
    DDBHandle(SuperName)
}

#[derive(Debug, Clone)]
pub struct ArgObj(u8);
#[derive(Debug, Clone)]
pub struct LocalObj(u8);
// Not actually doing anything to contain data, but does give us type guarantees, which is useful

#[derive(Debug, Clone)]
pub enum ComputationalData {
    Byte(u8),
    Word(u16),
    DWord(u32),
    QWord(u64),
    String(String),
    Zero,
    One,
    Ones,
    DefBuffer(DefBuffer),
    RevisionOp
}

impl AmlExecutable for DataRefObj {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue> {
        match *self {
            DataRefObj::DataObj(ref cd) => cd.execute(namespace, scope),
            _ => Some(AmlValue::Integer)
        }
    }
}

impl AmlExecutable for DataObj {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue> {
        match *self {
            DataObj::ComputationalData(ref cd) => cd.execute(namespace, scope),
            DataObj::DefPackage(ref pkg) => pkg.execute(namespace, scope),
            _ => Some(AmlValue::Integer)
        }
    }
}

impl AmlExecutable for ComputationalData {
    fn execute(&self, namespace: &mut AmlNamespace, scope: String) -> Option<AmlValue> {
        match *self {
            ComputationalData::Byte(b) => Some(AmlValue::IntegerConstant(b as u64)),
            ComputationalData::Word(w) => Some(AmlValue::IntegerConstant(w as u64)),
            ComputationalData::DWord(d) => Some(AmlValue::IntegerConstant(d as u64)),
            ComputationalData::QWord(q) => Some(AmlValue::IntegerConstant(q as u64)),
            ComputationalData::Zero => Some(AmlValue::IntegerConstant(0)),
            ComputationalData::One => Some(AmlValue::IntegerConstant(1)),
            ComputationalData::Ones => Some(AmlValue::IntegerConstant(0xFFFFFFFFFFFFFFFF)),
            ComputationalData::String(ref s) => Some(AmlValue::String(s.clone())),
            _ => Some(AmlValue::Integer)
        }
    }
}

pub fn parse_data_obj(data: &[u8]) -> Result<(DataObj, usize), AmlInternalError> {
    parser_selector! {
        data,
        parser_wrap!(DataObj::ComputationalData, parse_computational_data),
        parser_wrap!(DataObj::DefPackage, parse_def_package),
        parser_wrap!(DataObj::DefVarPackage, parse_def_var_package)
    };
    
    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_data_ref_obj(data: &[u8]) -> Result<(DataRefObj, usize), AmlInternalError> {
    parser_selector! {
        data,
        parser_wrap!(DataRefObj::DataObj, parse_data_obj),
        parser_wrap!(DataRefObj::ObjectReference, parse_term_arg),
        parser_wrap!(DataRefObj::DDBHandle, parse_super_name)
    };
    
    Err(AmlInternalError::AmlInvalidOpCode)
}

pub fn parse_arg_obj(data: &[u8]) -> Result<(ArgObj, usize), AmlInternalError> {
    match data[0] {
        0x68 ... 0x6E => Ok((ArgObj(data[0] - 0x68), 1 as usize)),
        _ => Err(AmlInternalError::AmlInvalidOpCode)
    }
}

pub fn parse_local_obj(data: &[u8]) -> Result<(LocalObj, usize), AmlInternalError> {
    match data[0] {
        0x60 ... 0x67 => Ok((LocalObj(data[0] - 0x60), 1 as usize)),
        _ => Err(AmlInternalError::AmlInvalidOpCode)
    }
}

fn parse_computational_data(data: &[u8]) -> Result<(ComputationalData, usize), AmlInternalError> {
    match data[0] {
        0x0A => Ok((ComputationalData::Byte(data[1]), 2 as usize)),
        0x0B => {
            let res = (data[1] as u16) +
                ((data[2] as u16) << 8);
            Ok((ComputationalData::Word(res), 3 as usize))
        },
        0x0C => {
            let res = (data[1] as u32) +
                ((data[2] as u32) << 8) +
                ((data[3] as u32) << 16) +
                ((data[4] as u32) << 24);
            Ok((ComputationalData::DWord(res), 5 as usize))
        },
        0x0D => {
            let mut cur_ptr: usize = 1;
            let mut cur_string: Vec<u8> = vec!();

            while data[cur_ptr] != 0x00 {
                cur_string.push(data[cur_ptr]);
                cur_ptr += 1;
            }

            match String::from_utf8(cur_string) {
                Ok(s) => Ok((ComputationalData::String(s.clone()), s.clone().len() + 2)),
                Err(_) => Err(AmlInternalError::AmlParseError("String data - invalid string"))
            }
        },
        0x0E => {
            let res = (data[1] as u64) +
                ((data[2] as u64) << 8) +
                ((data[3] as u64) << 16) +
                ((data[4] as u64) << 24) +
                ((data[5] as u64) << 32) +
                ((data[6] as u64) << 40) +
                ((data[7] as u64) << 48) +
                ((data[8] as u64) << 56);
            Ok((ComputationalData::QWord(res), 9 as usize))
        },
        0x00 => Ok((ComputationalData::Zero, 1 as usize)),
        0x01 => Ok((ComputationalData::One, 1 as usize)),
        0x5B => if data[1] == 0x30 {
            Ok((ComputationalData::RevisionOp, 2 as usize))
        } else {
            Err(AmlInternalError::AmlInvalidOpCode)
        },
        0xFF => Ok((ComputationalData::Ones, 1 as usize)),
        _ => match parse_def_buffer(data) {
            Ok((res, size)) => Ok((ComputationalData::DefBuffer(res), size)),
            Err(e) => Err(e)
        }
    }
}
