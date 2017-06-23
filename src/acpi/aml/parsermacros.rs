#[macro_export]
macro_rules! parser_selector {
    {$data:expr, $namespace:expr, $scope:expr, $func:expr} => {
        match $func($data, $namespace, $scope) {
            Ok(res) => return Ok(res),
            Err(AmlInternalError::AmlInvalidOpCode) => (),
            Err(e) => return Err(e)
        }
    };
    {$data:expr, $namespace:expr, $scope:expr, $func:expr, $($funcs:expr),+} => {
        parser_selector! {$data, $namespace, $scope, $func};
        parser_selector! {$data, $namespace, $scope, $($funcs),*};
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

#[macro_export]
macro_rules! parser_verify_value {
    ($val:expr) => {
        match $val.val {
            Some(s) => s,
            None => return Err(AmlInternalError::AmlValueError)
        }
    };
}

