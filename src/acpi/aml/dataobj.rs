
use collections::vec::Vec;
use collections::string::String;

use super::AmlInternalError;

use super::type2opcode::{parse_def_buffer, parse_def_package, DefBuffer, DefPackage};
use super::termlist::{parse_term_arg, TermArg};
use super::namestring::{parse_super_name, SuperName};


#[derive(Debug)]
pub enum DataObj {
    ComputationalData(ComputationalData),
    DefPackage(DefPackage)
}

#[derive(Debug)]
pub enum DataRefObj {
    DataObj(DataObj),
    ObjectReference(TermArg),
    DDBHandle(SuperName)
}

#[derive(Debug)]
pub struct ArgObj(u8);
#[derive(Debug)]
pub struct LocalObj(u8);
// Not actually doing anything to contain data, but does give us type guarantees, which is useful

#[derive(Debug)]
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

pub fn parse_data_obj(data: &[u8]) -> Result<(DataObj, usize), AmlInternalError> {
    match parse_computational_data(data) {
        Ok((res, size)) => return Ok((DataObj::ComputationalData(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_package(data) {
        Ok((res, size)) => return Ok((DataObj::DefPackage(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    Err(AmlInternalError::AmlParseError)
        // Rest currently isn't implemented
}

pub fn parse_data_ref_obj(data: &[u8]) -> Result<(DataRefObj, usize), AmlInternalError> {
    match parse_data_obj(data) {
        Ok((res, size)) => return Ok((DataRefObj::DataObj(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_term_arg(data) {
        Ok((res, size)) => return Ok((DataRefObj::ObjectReference(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }

    match parse_super_name(data) {
        Ok((res, size)) => return Ok((DataRefObj::DDBHandle(res), size)),
        Err(AmlInternalError::AmlParseError) => Err(AmlInternalError::AmlDeferredLoad),
        Err(AmlInternalError::AmlDeferredLoad) => Err(AmlInternalError::AmlDeferredLoad)
    }
}

pub fn parse_arg_obj(data: &[u8]) -> Result<(ArgObj, usize), AmlInternalError> {
    match data[0] {
        0x68 ... 0x6E => Ok((ArgObj(data[0] - 0x68), 1 as usize)),
        _ => Err(AmlInternalError::AmlParseError)
    }
}

pub fn parse_local_obj(data: &[u8]) -> Result<(LocalObj, usize), AmlInternalError> {
    match data[0] {
        0x60 ... 0x67 => Ok((LocalObj(data[0] - 0x60), 1 as usize)),
        _ => Err(AmlInternalError::AmlParseError)
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
                Err(_) => Err(AmlInternalError::AmlParseError)
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
            Err(AmlInternalError::AmlParseError)
        },
        0xFF => Ok((ComputationalData::Ones, 1 as usize)),
        _ => {
            match parse_def_buffer(data) {
                Ok((res, size)) => return Ok((ComputationalData::DefBuffer(res), size)),
                Err(AmlInternalError::AmlParseError) => (),
                Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
            }

            Err(AmlInternalError::AmlParseError)
        }
    }
}
