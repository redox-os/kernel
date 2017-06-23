use super::AmlValue;

pub type ParseResult = Result<AmlParseType, AmlInternalError>;

pub struct AmlParseType {
    val: Option<AmlValue>,
    len: usize
}

// TODO: make private
pub enum AmlInternalError {
    AmlParseError(&'static str),
    AmlInvalidOpCode,
    AmlValueError,
    AmlDeferredLoad
}
