use collections::vec::Vec;

use super::AmlInternalError;

use super::pkglength::parse_pkg_length;
use super::termlist::{parse_term_arg, parse_term_list, TermObj, TermArg};

#[derive(Debug)]
pub enum Type1OpCode {
    DefIfElse {
        if_block: IfBlock,
        else_block: IfBlock
    },
    DefWhile {
        predicate: TermArg,
        block: Vec<TermObj>
    },
    DefReturn(TermArg),
    DeferredLoad(Vec<u8>)
}

#[derive(Debug)]
pub enum IfBlock {
    If {
        predicate: TermArg,
        if_block: Vec<TermObj>
    },
    Else(Vec<TermObj>),
    NoBlock,
    DeferredLoad(Vec<u8>)
}

pub fn parse_type1_opcode(data: &[u8]) -> Result<(Type1OpCode, usize), AmlInternalError> {
    match parse_def_if_else(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    match parse_def_return(data) {
        Ok(res) => return Ok(res),
        Err(AmlInternalError::AmlParseError) => (),
        Err(AmlInternalError::AmlDeferredLoad) => return Err(AmlInternalError::AmlDeferredLoad)
    }
    
    parse_def_while(data)
}

fn parse_def_if_else(data: &[u8]) -> Result<(Type1OpCode, usize), AmlInternalError> {
    if data[0] != 0xA0 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;

    let if_block = match parse_term_arg(&data[1 + pkg_length_len..]) {
        Ok((predicate, predicate_len)) => {
            match parse_term_list(&data[1 + pkg_length_len + predicate_len .. 1 + pkg_length]) {
                Ok(if_block) => IfBlock::If {predicate, if_block},
                Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
                Err(AmlInternalError::AmlDeferredLoad) => 
                    IfBlock::DeferredLoad(data[0 .. pkg_length + 1].to_vec())
            }
        },
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            IfBlock::DeferredLoad(data[0 .. pkg_length + 1].to_vec())
    };
    
    let (else_block, else_block_len) = parse_def_else(&data[1 + pkg_length..])?;
    
    return Ok((Type1OpCode::DefIfElse {if_block, else_block},
               pkg_length + else_block_len + 1));
}

fn parse_def_else(data: &[u8]) -> Result<(IfBlock, usize), AmlInternalError> {
    if data[0] != 0xA1 {
        return Ok((IfBlock::NoBlock, 0));
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    match parse_term_list(&data[1 + pkg_length_len .. 1 + pkg_length]) {
        Ok(term_list) => Ok((IfBlock::Else(term_list), pkg_length)),
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            Ok((IfBlock::DeferredLoad(data[0 .. pkg_length + 1].to_vec()), 1 + pkg_length))
    }
}

fn parse_def_while(data: &[u8]) -> Result<(Type1OpCode, usize), AmlInternalError> {
    if data[0] != 0xA2 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[1..])?;
    let (predicate, predicate_len) = match parse_term_arg(&data[1 + pkg_length_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((Type1OpCode::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 1 + pkg_length))
    };
    let block = match parse_term_list(&data[1 + pkg_length_len + predicate_len .. 1 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlParseError) => return Err(AmlInternalError::AmlParseError),
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((Type1OpCode::DeferredLoad(data[0 .. 1 + pkg_length].to_vec()), 1 + pkg_length))
    };

    Ok((Type1OpCode::DefWhile {predicate, block}, pkg_length + 1))
}

fn parse_def_return(data: &[u8]) -> Result<(Type1OpCode, usize), AmlInternalError> {
    if data[0] != 0xA4 {
        return Err(AmlInternalError::AmlParseError);
    }

    let (arg_object, arg_object_len) = parse_term_arg(&data[1..])?;

    Ok((Type1OpCode::DefReturn(arg_object), 1 + arg_object_len))
}