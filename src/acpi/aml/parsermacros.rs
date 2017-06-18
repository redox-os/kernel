#[macro_export]
macro_rules! parser_selector {
    {$data:expr, $func:expr} => {
        match $func($data) {
            Ok(res) => return Ok(res),
            Err(AmlInternalError::AmlInvalidOpCode) => (),
            Err(e) => return Err(e)
        }
    };
    {$data:expr, $func:expr, $($funcs:expr),+} => {
        parser_selector! {$data, $func};
        parser_selector! {$data, $($funcs),*};
    };
}

#[macro_export]
macro_rules! parser_wrap {
    ($wrap:expr, $func:expr) => {
        |data| { 
            match $func(data) {
                Ok((res, size)) => Ok(($wrap(res), size)),
                Err(e) => Err(e)
            }
        }
    };
}

#[macro_export]
macro_rules! parser_opcode {
    ($data:expr, $opcode:expr) => {
        if $data[0] != $opcode {
            return Err(AmlInternalError::AmlInvalidOpCode);
        }
    };
    ($data:expr, $opcode:expr, $alternate_opcode:expr) => {
        if $data[0] != $opcode && $data[0] != $alternate_opcode {
            return Err(AmlInternalError::AmlInvalidOpCode);
        }
    };
}

#[macro_export]
macro_rules! parser_opcode_extended {
    ($data:expr, $opcode:expr) => {
        if $data[0] != 0x5B || $data[1] != $opcode {
            return Err(AmlInternalError::AmlInvalidOpCode);
        }
    };
}
