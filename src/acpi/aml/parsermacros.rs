#[macro_export]
macro_rules! parser_selector {
    {$data:expr, $namespace:expr, $scope:expr, $func:expr} => {
        match $func($data, $namespace, $scope) {
            Ok(res) => return Ok(res),
            Err(AmlError::AmlInvalidOpCode) => (),
            Err(e) => return Err(e)
        }
    };
    {$data:expr, $namespace:expr, $scope:expr, $func:expr, $($funcs:expr),+} => {
        parser_selector! {$data, $namespace, $scope, $func};
        parser_selector! {$data, $namespace, $scope, $($funcs),*};
    };
}

macro_rules! parser_selector_simple {
    {$data:expr, $func:expr} => {
        match $func($data) {
            Ok(res) => return Ok(res),
            Err(AmlError::AmlInvalidOpCode) => (),
            Err(e) => return Err(e)
        }
    };
    {$data:expr, $func:expr, $($funcs:expr),+} => {
        parser_selector_simple! {$data, $func};
        parser_selector_simple! {$data, $($funcs),*};
    };
}

#[macro_export]
macro_rules! parser_wrap {
    ($wrap:expr, $func:expr) => {
        |data, namespace, scope| { 
            match $func(data) {
                Ok(res) => Ok(AmlParseTypeGeneric {
                    val: $wrap(res.val),
                    len: res.len
                }),
                Err(e) => Err(e)
            }
        }
    };
}

#[macro_export]
macro_rules! parser_opcode {
    ($data:expr, $opcode:expr) => {
        if $data[0] != $opcode {
            return Err(AmlError::AmlInvalidOpCode);
        }
    };
    ($data:expr, $opcode:expr, $alternate_opcode:expr) => {
        if $data[0] != $opcode && $data[0] != $alternate_opcode {
            return Err(AmlError::AmlInvalidOpCode);
        }
    };
}

#[macro_export]
macro_rules! parser_opcode_extended {
    ($data:expr, $opcode:expr) => {
        if $data[0] != 0x5B || $data[1] != $opcode {
            return Err(AmlError::AmlInvalidOpCode);
        }
    };
}

#[macro_export]
macro_rules! parser_verify_value {
    ($val:expr) => {
        match $val.val {
            Some(s) => s,
            None => return Err(AmlError::AmlValueError)
        }
    };
}

