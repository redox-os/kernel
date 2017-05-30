use super::AmlInternalError;

use super::type2opcode::{parse_def_buffer, DefBuffer};

pub enum DataObj {
    ComputationalData(ComputationalData)
}

pub enum DataRefObj {
    DataObj(DataObj)
}

pub struct ArgObj(u8);
pub struct LocalObj(u8);
// Not actually doing anything to contain data, but does give us type guarantees, which is useful

enum ComputationalData {
    Byte(u8),
    Word(u16),
    DWord(u32),
    QWord(u64),
    Zero,
    One,
    Ones,
    DefBuffer(DefBuffer)
}

pub fn parse_data_obj(data: &[u8]) -> Result<(DataObj, usize), AmlInternalError> {
    match parse_computational_data(data) {
        Ok((res, size)) => return Ok((DataObj::ComputationalData(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    Err(AmlInternalError::AmlParseError)
        // Rest currently isn't implemented
}

pub fn parse_data_ref_obj(data: &[u8]) -> Result<(DataRefObj, usize), AmlInternalError> {
    println!("{}", data[0]);
    match parse_data_obj(data) {
        Ok((res, size)) => return Ok((DataRefObj::DataObj(res), size)),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    Err(AmlInternalError::AmlParseError)
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
