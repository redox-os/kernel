use alloc::boxed::Box;
use collections::string::String;
use collections::vec::Vec;
use core::str::FromStr;

use collections::btree_map::BTreeMap;

use super::{AmlInternalError, AmlExecutable, AmlValue, get_namespace_string};
use super::namespace::FieldSelector;
use super::namestring::{parse_name_string, parse_name_seg, SuperName};
use super::termlist::{parse_term_arg, parse_term_list, parse_object_list, TermArg, TermObj, Object};
use super::pkglength::parse_pkg_length;
use super::type2opcode::{parse_def_buffer, DefBuffer};

#[derive(Debug, Clone)]
pub enum NamedObj {
    DefBankField {
        region_name: String,
        bank_name: String,
        bank_value: TermArg,
        flags: FieldFlags,
        field_list: Vec<FieldElement>
    },
    DefCreateBitField {
        name: String,
        source_buf: TermArg,
        bit_index: TermArg
    },
    DefCreateByteField {
        name: String,
        source_buf: TermArg,
        byte_index: TermArg
    },
    DefCreateWordField {
        name: String,
        source_buf: TermArg,
        byte_index: TermArg
    },
    DefCreateDWordField {
        name: String,
        source_buf: TermArg,
        byte_index: TermArg
    },
    DefCreateQWordField {
        name: String,
        source_buf: TermArg,
        byte_index: TermArg
    },
    DefCreateField {
        name: String,
        source_buf: TermArg,
        bit_index: TermArg,
        num_bits: TermArg
    },
    DefDataRegion {
        name: String,
        signature: TermArg,
        oem_id: TermArg,
        oem_table_id: TermArg
    },
    DefDevice {
        name: String,
        obj_list: Vec<Object>
    },
    DefEvent {
        name: String
    },
    DefOpRegion {
        name: String,
        region: RegionSpace,
        offset: TermArg,
        len: TermArg
    },
    DefField {
        name: String,
        flags: FieldFlags,
        field_list: Vec<FieldElement>
    },
    DefIndexField {
        idx_name: String,
        data_name: String,
        flags: FieldFlags,
        field_list: Vec<FieldElement>
    },
    DefMethod {
        name: String,
        method: Method
    },
    DefMutex {
        name: String,
        sync_level: u8
    },
    DefPowerRes {
        name: String,
        system_level: u8,
        resource_order: u16,
        obj_list: Vec<Object>
    },
    DefProcessor {
        name: String,
        proc_id: u8,
        p_blk_addr: u32,
        p_blk_len: u8,
        obj_list: Vec<Object>
    },
    DefThermalZone {
        name: String,
        obj_list: Vec<Object>
    },
    DeferredLoad(Vec<u8>)
}

#[derive(Debug, Clone)]
pub struct Method {
    arg_count: u8,
    serialized: bool,
    sync_level: u8,
    term_list: Vec<TermObj>
}

impl AmlExecutable for NamedObj {
    fn execute(&self, namespace: &mut BTreeMap<String, AmlValue>, scope: String) -> Option<AmlValue> {
        match *self {
            NamedObj::DefBankField { ref region_name, ref bank_name, ref bank_value, ref flags, ref field_list } => {
                let mut offset: usize = 0;
                let mut connection = AmlValue::Uninitialized;
                let bank_val = if let Some(b) = bank_value.execute(namespace, scope.clone()) {
                    Box::new(b)
                } else {
                    return None;
                };

                for f in field_list {
                    match *f {
                        FieldElement::ReservedField { length } => offset += length,
                        FieldElement::ConnectFieldNameString(ref name) => connection =
                            AmlValue::ObjectReference(SuperName::NameString(name.clone())),
                        FieldElement::ConnectFieldBufferData(ref buf) => {
                            connection = match buf.execute(namespace, scope.clone()) {
                                Some(c) => c,
                                None => return None
                            };
                        },
                        FieldElement::NamedField { name: ref field_name, length } => {
                            let local_scope_string = get_namespace_string(scope.clone(),
                                                                          field_name.clone());
                            namespace.insert(local_scope_string, AmlValue::FieldUnit {
                                selector: FieldSelector::Bank {
                                    region: region_name.clone(),
                                    bank_selector: bank_val.clone()
                                },
                                connection: Box::new(connection.clone()),
                                flags: flags.clone(),
                                offset: offset.clone(),
                                length: length.clone()
                            });

                            offset += length;
                        },
                        _ => ()
                    }
                }
            },
            NamedObj::DefIndexField { ref idx_name, ref data_name, ref flags, ref field_list } => {
                let mut offset: usize = 0;
                let mut connection = AmlValue::Uninitialized;

                for f in field_list {
                    match *f {
                        FieldElement::ReservedField { length } => offset += length,
                        FieldElement::ConnectFieldNameString(ref name) => connection =
                            AmlValue::ObjectReference(SuperName::NameString(name.clone())),
                        FieldElement::ConnectFieldBufferData(ref buf) => {
                            connection = match buf.execute(namespace, scope.clone()) {
                                Some(c) => c,
                                None => return None
                            };
                        },
                        FieldElement::NamedField { name: ref field_name, length } => {
                            let local_scope_string = get_namespace_string(scope.clone(),
                                                                          field_name.clone());
                            namespace.insert(local_scope_string, AmlValue::FieldUnit {
                                selector: FieldSelector::Index {
                                    index_selector: idx_name.clone(),
                                    data_selector: data_name.clone()
                                },
                                connection: Box::new(connection.clone()),
                                flags: flags.clone(),
                                offset: offset.clone(),
                                length: length.clone()
                            });

                            offset += length;
                        },
                        _ => ()
                    }
                }
            },
            NamedObj::DefCreateBitField { ref name, ref source_buf, ref bit_index } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                
                let resolved_source_buf = match source_buf.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_index = match bit_index.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::BufferField {
                    source_buf: resolved_source_buf,
                    index: resolved_index,
                    length: Box::new(AmlValue::IntegerConstant(1))
                });
            },
            NamedObj::DefCreateByteField { ref name, ref source_buf, ref byte_index } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                
                let resolved_source_buf = match source_buf.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_index = match byte_index.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::BufferField {
                    source_buf: resolved_source_buf,
                    index: resolved_index,
                    length: Box::new(AmlValue::IntegerConstant(8))
                });
            },
            NamedObj::DefCreateWordField { ref name, ref source_buf, ref byte_index } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                
                let resolved_source_buf = match source_buf.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_index = match byte_index.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::BufferField {
                    source_buf: resolved_source_buf,
                    index: resolved_index,
                    length: Box::new(AmlValue::IntegerConstant(16))
                });
            },
            NamedObj::DefCreateDWordField { ref name, ref source_buf, ref byte_index } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                
                let resolved_source_buf = match source_buf.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_index = match byte_index.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::BufferField {
                    source_buf: resolved_source_buf,
                    index: resolved_index,
                    length: Box::new(AmlValue::IntegerConstant(32))
                });
            },
            NamedObj::DefCreateQWordField { ref name, ref source_buf, ref byte_index } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                
                let resolved_source_buf = match source_buf.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_index = match byte_index.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::BufferField {
                    source_buf: resolved_source_buf,
                    index: resolved_index,
                    length: Box::new(AmlValue::IntegerConstant(64))
                });
            },
            NamedObj::DefCreateField { ref name, ref source_buf, ref bit_index, ref num_bits } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                
                let resolved_source_buf = match source_buf.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_index = match bit_index.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };
                let resolved_length = match num_bits.execute(namespace, scope.clone()) {
                    Some(r) => Box::new(r),
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::BufferField {
                    source_buf: resolved_source_buf,
                    index: resolved_index,
                    length: resolved_length
                });
            },
            NamedObj::DefDataRegion { ref name, ref signature, ref oem_id, ref oem_table_id } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());

                namespace.insert(local_scope_string, AmlValue::OperationRegion {
                    region: RegionSpace::SystemMemory,
                    offset: Box::new(AmlValue::IntegerConstant(0)),
                    len: Box::new(AmlValue::IntegerConstant(0))
                });
            },
            NamedObj::DefOpRegion { ref name, ref region, ref offset, ref len } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());

                let resolved_offset = match offset.execute(namespace, scope.clone()) {
                    Some(r) => r,
                    _ => return None
                };

                let resolved_len = match len.execute(namespace, scope.clone()) {
                    Some(r) => r,
                    _ => return None
                };

                namespace.insert(local_scope_string, AmlValue::OperationRegion {
                    region: *region,
                    offset: Box::new(resolved_offset),
                    len: Box::new(resolved_len)
                });
            },
            NamedObj::DefField { ref name, ref flags, ref field_list } => {
                let mut offset: usize = 0;
                let mut connection = AmlValue::Uninitialized;

                for f in field_list {
                    match *f {
                        FieldElement::ReservedField { length } => offset += length,
                        FieldElement::ConnectFieldNameString(ref name) => connection =
                            AmlValue::ObjectReference(SuperName::NameString(name.clone())),
                        FieldElement::ConnectFieldBufferData(ref buf) => {
                            connection = match buf.execute(namespace, scope.clone()) {
                                Some(c) => c,
                                None => return None
                            };
                        },
                        FieldElement::NamedField { name: ref field_name, length } => {
                            let local_scope_string = get_namespace_string(scope.clone(),
                                                                          field_name.clone());
                            namespace.insert(local_scope_string, AmlValue::FieldUnit {
                                selector: FieldSelector::Region(name.clone()),
                                connection: Box::new(connection.clone()),
                                flags: flags.clone(),
                                offset: offset.clone(),
                                length: length.clone()
                            });

                            offset += length;
                        },
                        _ => ()
                    }
                }
            },
            NamedObj::DefMethod { ref name, ref method } => {
                let local_scope_string = get_namespace_string(scope.clone(), name.clone());
                namespace.insert(local_scope_string, AmlValue::Method(method.clone()));
            },
            NamedObj::DefDevice { ref name, ref obj_list } => {
                let local_scope_string = get_namespace_string(scope, name.clone());

                let mut local_namespace = BTreeMap::new();
                obj_list.execute(&mut local_namespace, String::new());

                namespace.insert(local_scope_string, AmlValue::Device(local_namespace));
            },
            NamedObj::DefThermalZone { ref name, ref obj_list } => {
                let local_scope_string = get_namespace_string(scope, name.clone());

                let mut local_namespace = BTreeMap::new();
                obj_list.execute(&mut local_namespace, String::new());

                namespace.insert(local_scope_string, AmlValue::ThermalZone(local_namespace));
            },
            NamedObj::DefProcessor { ref name, proc_id, p_blk_addr, p_blk_len, ref obj_list } => {
                let local_scope_string = get_namespace_string(scope, name.clone());

                let mut local_namespace = BTreeMap::new();
                obj_list.execute(&mut local_namespace, String::new());

                namespace.insert(local_scope_string, AmlValue::Processor {
                    proc_id: proc_id,
                    p_blk: if p_blk_len > 0 { Some(p_blk_addr) } else { None },
                    obj_list: local_namespace
                });
            },
            NamedObj::DefPowerRes { ref name, system_level, resource_order, ref obj_list } => {
                let local_scope_string = get_namespace_string(scope, name.clone());

                let mut local_namespace = BTreeMap::new();
                obj_list.execute(&mut local_namespace, String::new());

                namespace.insert(local_scope_string, AmlValue::PowerResource {
                    system_level,
                    resource_order,
                    obj_list: local_namespace
                });
            },
            NamedObj::DefMutex { ref name, sync_level } => {
                let local_scope_string = get_namespace_string(scope, name.clone());
                namespace.insert(local_scope_string, AmlValue::Mutex(sync_level));
            },
            NamedObj::DefEvent { ref name } => {
                let local_scope_string = get_namespace_string(scope, name.clone());
                namespace.insert(local_scope_string, AmlValue::Event);
            },
            _ => ()
        }

        None
    }
}

#[derive(Debug, Copy, Clone)]
pub enum RegionSpace {
    SystemMemory,
    SystemIO,
    PCIConfig,
    EmbeddedControl,
    SMBus,
    SystemCMOS,
    PciBarTarget,
    IPMI,
    GeneralPurposeIO,
    GenericSerialBus,
    UserDefined(u8)
}

#[derive(Debug, Clone)]
pub struct FieldFlags {
    access_type: AccessType,
    lock_rule: bool,
    update_rule: UpdateRule
}

#[derive(Debug, Clone)]
pub enum AccessType {
    AnyAcc,
    ByteAcc,
    WordAcc,
    DWordAcc,
    QWordAcc,
    BufferAcc
}

#[derive(Debug, Clone)]
pub enum UpdateRule {
    Preserve,
    WriteAsOnes,
    WriteAsZeros
}

#[derive(Debug, Clone)]
pub enum FieldElement {
    NamedField {
        name: String,
        length: usize
    },
    ReservedField {
        length: usize
    },
    AccessField {
        access_type: AccessType,
        access_attrib: AccessAttrib
    },
    ConnectFieldNameString(String),
    ConnectFieldBufferData(DefBuffer),
}

#[derive(Debug, Clone)]
pub enum AccessAttrib {
    AttribBytes(u8),
    AttribRawBytes(u8),
    AttribRawProcessBytes(u8),
    AttribQuick,
    AttribSendReceive,
    AttribByte,
    AttribWord,
    AttribBlock,
    AttribProcessCall,
    AttribBlockProcessCall
}

pub fn parse_named_obj(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_selector! {
        data,
        parse_def_bank_field,
        parse_def_create_bit_field,
        parse_def_create_byte_field,
        parse_def_create_word_field,
        parse_def_create_dword_field,
        parse_def_create_qword_field,
        parse_def_create_field,
        parse_def_data_region,
        parse_def_event,
        parse_def_device,
        parse_def_op_region,
        parse_def_field,
        parse_def_index_field,
        parse_def_method,
        parse_def_mutex,
        parse_def_power_res,
        parse_def_processor,
        parse_def_thermal_zone
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

fn parse_def_bank_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x87);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (region_name, region_name_len) = match parse_name_string(
            &data[2 + pkg_length_len .. 2 + pkg_length]) {
        Ok(res) => res,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let (bank_name, bank_name_len) = match parse_name_string(
            &data[2 + pkg_length_len + region_name_len .. 2 + pkg_length]) {
        Ok(res) => res,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let (bank_value, bank_value_len) = match parse_term_arg(
            &data[2 + pkg_length_len + region_name_len .. 2 + pkg_length]) {
        Ok(res) => res,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let flags_raw = data[2 + pkg_length_len + region_name_len + bank_name_len + bank_value_len];
    let flags = FieldFlags {
        access_type: match flags_raw & 0x0F {
            0 => AccessType::AnyAcc,
            1 => AccessType::ByteAcc,
            2 => AccessType::WordAcc,
            3 => AccessType::DWordAcc,
            4 => AccessType::QWordAcc,
            5 => AccessType::BufferAcc,
            _ => return Err(AmlInternalError::AmlParseError("BankField - invalid access type"))
        },
        lock_rule: (flags_raw & 0x10) == 0x10,
        update_rule: match (flags_raw & 0x60) >> 5 {
            0 => UpdateRule::Preserve,
            1 => UpdateRule::WriteAsOnes,
            2 => UpdateRule::WriteAsZeros,
            _ => return Err(AmlInternalError::AmlParseError("BankField - invalid update rule"))
        }
    };

    let field_list = match parse_field_list(
        &data[3 + pkg_length_len + region_name_len + bank_name_len + bank_value_len ..
              2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefBankField {region_name, bank_name, bank_value, flags, field_list},
        2 + pkg_length))
}

fn parse_def_create_bit_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode!(data, 0x8D);

    let (source_buf, source_buf_len) = parse_term_arg(&data[1..])?;
    let (bit_index, bit_index_len) = parse_term_arg(&data[1 + source_buf_len..])?;
    let (name, name_len) = parse_name_string(&data[1 + source_buf_len + bit_index_len..])?;

    Ok((NamedObj::DefCreateBitField {name, source_buf, bit_index},
        1 + source_buf_len + bit_index_len + name_len))
}

fn parse_def_create_byte_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode!(data, 0x8C);

    let (source_buf, source_buf_len) = parse_term_arg(&data[1..])?;
    let (byte_index, byte_index_len) = parse_term_arg(&data[1 + source_buf_len..])?;
    let (name, name_len) = parse_name_string(&data[1 + source_buf_len + byte_index_len..])?;

    Ok((NamedObj::DefCreateByteField {name, source_buf, byte_index},
        1 + source_buf_len + byte_index_len + name_len))
}

fn parse_def_create_word_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode!(data, 0x8B);

    let (source_buf, source_buf_len) = parse_term_arg(&data[1..])?;
    let (byte_index, byte_index_len) = parse_term_arg(&data[1 + source_buf_len..])?;
    let (name, name_len) = parse_name_string(&data[1 + source_buf_len + byte_index_len..])?;

    Ok((NamedObj::DefCreateWordField {name, source_buf, byte_index},
        1 + source_buf_len + byte_index_len + name_len))
}

fn parse_def_create_dword_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode!(data, 0x8A);

    let (source_buf, source_buf_len) = parse_term_arg(&data[1..])?;
    let (byte_index, byte_index_len) = parse_term_arg(&data[1 + source_buf_len..])?;
    let (name, name_len) = parse_name_string(&data[1 + source_buf_len + byte_index_len..])?;

    Ok((NamedObj::DefCreateDWordField {name, source_buf, byte_index},
        1 + source_buf_len + byte_index_len + name_len))
}

fn parse_def_create_qword_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode!(data, 0x8F);

    let (source_buf, source_buf_len) = parse_term_arg(&data[1..])?;
    let (byte_index, byte_index_len) = parse_term_arg(&data[1 + source_buf_len..])?;
    let (name, name_len) = parse_name_string(&data[1 + source_buf_len + byte_index_len..])?;

    Ok((NamedObj::DefCreateQWordField {name, source_buf, byte_index},
        1 + source_buf_len + byte_index_len + name_len))
}

fn parse_def_create_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x13);

    let (source_buf, source_buf_len) = parse_term_arg(&data[2..])?;
    let (bit_index, bit_index_len) = parse_term_arg(&data[2 + source_buf_len..])?;
    let (num_bits, num_bits_len) = parse_term_arg(&data[2 + source_buf_len + bit_index_len..])?;
    let (name, name_len) = parse_name_string(
        &data[2 + source_buf_len + bit_index_len + num_bits_len..])?;

    Ok((NamedObj::DefCreateField {name, source_buf, bit_index, num_bits},
        2 + source_buf_len + bit_index_len + num_bits_len + name_len))
}

fn parse_def_data_region(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x88);

    let (name, name_len) = parse_name_string(&data[2..])?;
    let (signature, signature_len) = parse_term_arg(&data[2 + name_len..])?;
    let (oem_id, oem_id_len) = parse_term_arg(&data[2 + name_len + signature_len..])?;
    let (oem_table_id, oem_table_id_len) = parse_term_arg(
        &data[2 + name_len + signature_len + oem_id_len..])?;

    Ok((NamedObj::DefDataRegion {name, signature, oem_id, oem_table_id},
        2 + name_len + signature_len + oem_id_len + oem_table_id_len))
}

fn parse_def_event(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x02);

    let (name, name_len) = parse_name_string(&data[2..])?;

    Ok((NamedObj::DefEvent {name}, 2 + name_len))
}

fn parse_def_device(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x82);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_length_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let obj_list = match parse_object_list(&data[2 + pkg_length_len + name_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefDevice {name, obj_list}, 2 + pkg_length_len))
}

fn parse_def_op_region(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x80);

    let (name, name_len) = parse_name_string(&data[2..])?;
    let region = match data[2 + name_len] {
        0x00 => RegionSpace::SystemMemory,
        0x01 => RegionSpace::SystemIO,
        0x02 => RegionSpace::PCIConfig,
        0x03 => RegionSpace::EmbeddedControl,
        0x04 => RegionSpace::SMBus,
        0x05 => RegionSpace::SystemCMOS,
        0x06 => RegionSpace::PciBarTarget,
        0x07 => RegionSpace::IPMI,
        0x08 => RegionSpace::GeneralPurposeIO,
        0x09 => RegionSpace::GenericSerialBus,
        0x80 ... 0xFF => RegionSpace::UserDefined(data[2 + name_len]),
        _ => return Err(AmlInternalError::AmlParseError("OpRegion - invalid region"))
    };

    let (offset, offset_len) = parse_term_arg(&data[3 + name_len..])?;
    let (len, len_len) = parse_term_arg(&data[3 + name_len + offset_len..])?;

    Ok((NamedObj::DefOpRegion {name, region, offset, len}, 3 + name_len + offset_len + len_len))
}

fn parse_def_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x81);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_length_len .. 2 + pkg_length])  {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let flags_raw = data[2 + pkg_length_len + name_len];
    let flags = FieldFlags {
        access_type: match flags_raw & 0x0F {
            0 => AccessType::AnyAcc,
            1 => AccessType::ByteAcc,
            2 => AccessType::WordAcc,
            3 => AccessType::DWordAcc,
            4 => AccessType::QWordAcc,
            5 => AccessType::BufferAcc,
            _ => return Err(AmlInternalError::AmlParseError("Field - Invalid access type"))
        },
        lock_rule: (flags_raw & 0x10) == 0x10,
        update_rule: match (flags_raw & 0x60) >> 5 {
            0 => UpdateRule::Preserve,
            1 => UpdateRule::WriteAsOnes,
            2 => UpdateRule::WriteAsZeros,
            _ => return Err(AmlInternalError::AmlParseError("Field - Invalid update rule"))
        }
    };

    let field_list = match parse_field_list(&data[3 + pkg_length_len + name_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefField {name, flags, field_list}, 2 + pkg_length))
}

fn parse_def_index_field(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x86);

    let (pkg_length, pkg_length_len) = parse_pkg_length(&data[2..])?;
    let (idx_name, idx_name_len) = match parse_name_string(
        &data[2 + pkg_length_len .. 2 + pkg_length])  {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let (data_name, data_name_len) = match parse_name_string(
        &data[2 + pkg_length_len + idx_name_len .. 2 + pkg_length])  {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    let flags_raw = data[2 + pkg_length_len + idx_name_len + data_name_len];
    let flags = FieldFlags {
        access_type: match flags_raw & 0x0F {
            0 => AccessType::AnyAcc,
            1 => AccessType::ByteAcc,
            2 => AccessType::WordAcc,
            3 => AccessType::DWordAcc,
            4 => AccessType::QWordAcc,
            5 => AccessType::BufferAcc,
            _ => return Err(AmlInternalError::AmlParseError("IndexField - Invalid access type"))
        },
        lock_rule: (flags_raw & 0x10) == 0x10,
        update_rule: match (flags_raw & 0x60) >> 5 {
            0 => UpdateRule::Preserve,
            1 => UpdateRule::WriteAsOnes,
            2 => UpdateRule::WriteAsZeros,
            _ => return Err(AmlInternalError::AmlParseError("IndexField - Invalid update rule"))
        }
    };

    let field_list = match parse_field_list(
        &data[3 + pkg_length_len + idx_name_len + data_name_len .. 2 + pkg_length]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_length].to_vec()), 2 + pkg_length)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefIndexField {idx_name, data_name, flags, field_list}, 2 + pkg_length))
}

fn parse_field_list(data: &[u8]) -> Result<Vec<FieldElement>, AmlInternalError> {
    let mut terms: Vec<FieldElement> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        let (res, len) = match parse_field_element(&data[current_offset..]) {
            Ok(r) => r,
            Err(AmlInternalError::AmlInvalidOpCode) =>
                return Err(AmlInternalError::AmlParseError("FieldList - no valid field")),
            Err(e) => return Err(e)
        };

        terms.push(res);
        current_offset += len;
    }

    Ok(terms)
}

fn parse_field_element(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    parser_selector! {
        data,
        parse_named_field,
        parse_reserved_field,
        parse_access_field,
        parse_connect_field
    };

    Err(AmlInternalError::AmlInvalidOpCode)
}

fn parse_named_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    let (name_seg, name_seg_len) = parse_name_seg(&data[0..4])?;
    let name = match String::from_utf8(name_seg) {
        Ok(s) => s,
        Err(_) => return Err(AmlInternalError::AmlParseError("NamedField - invalid name"))
    };
    let (length, length_len) = parse_pkg_length(&data[4..])?;

    Ok((FieldElement::NamedField {name, length}, 4 + length_len))
}

fn parse_reserved_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    parser_opcode!(data, 0x00);

    let (length, length_len) = parse_pkg_length(&data[1..])?;
    Ok((FieldElement::ReservedField {length}, 1 + length_len))
}

fn parse_access_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    parser_opcode!(data, 0x01, 0x03);

    let flags_raw = data[1];
    let access_type = match flags_raw & 0x0F {
        0 => AccessType::AnyAcc,
        1 => AccessType::ByteAcc,
        2 => AccessType::WordAcc,
        3 => AccessType::DWordAcc,
        4 => AccessType::QWordAcc,
        5 => AccessType::BufferAcc,
        _ => return Err(AmlInternalError::AmlParseError("AccessField - Invalid access type"))
    };

    let access_attrib = match (flags_raw & 0xC0) >> 6 {
        0 => match data[2] {
            0x02 => AccessAttrib::AttribQuick,
            0x04 => AccessAttrib::AttribSendReceive,
            0x06 => AccessAttrib::AttribByte,
            0x08 => AccessAttrib::AttribWord,
            0x0A => AccessAttrib::AttribBlock,
            0x0B => AccessAttrib::AttribBytes(data[3]),
            0x0C => AccessAttrib::AttribProcessCall,
            0x0D => AccessAttrib::AttribBlockProcessCall,
            0x0E => AccessAttrib::AttribRawBytes(data[3]),
            0x0F => AccessAttrib::AttribRawProcessBytes(data[3]),
            _ => return Err(AmlInternalError::AmlParseError("AccessField - Invalid access attrib"))
        },
        1 => AccessAttrib::AttribBytes(data[2]),
        2 => AccessAttrib::AttribRawBytes(data[2]),
        3 => AccessAttrib::AttribRawProcessBytes(data[2]),
        _ => return Err(AmlInternalError::AmlParseError("AccessField - Invalid access attrib"))
            // This should never happen but the compiler bitches if I don't cover this
    };

    return Ok((FieldElement::AccessField {access_type, access_attrib}, if data[0] == 0x01 {
        3 as usize
    } else {
        4 as usize
    }))
}

fn parse_connect_field(data: &[u8]) -> Result<(FieldElement, usize), AmlInternalError> {
    parser_opcode!(data, 0x02);

    match parse_def_buffer(&data[1..]) {
        Ok((buf, buf_len)) => return Ok((FieldElement::ConnectFieldBufferData(buf), buf_len + 1)),
        Err(AmlInternalError::AmlInvalidOpCode) => (),
        Err(e) => return Err(e)
    }

    match parse_name_string(&data[1..]) {
        Ok((name, name_len)) => Ok((FieldElement::ConnectFieldNameString(name), name_len + 1)),
        Err(AmlInternalError::AmlInvalidOpCode) => Err(AmlInternalError::AmlParseError("ConnectField - unable to match field")),
        Err(e) => Err(e)
    }
}

fn parse_def_method(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode!(data, 0x14);

    let (pkg_len, pkg_len_len) = parse_pkg_length(&data[1..])?;
    let (name, name_len) = match parse_name_string(&data[1 + pkg_len_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_len].to_vec()), 1 + pkg_len)),
        Err(e) => return Err(e)
    };
    let flags = data[1 + pkg_len_len + name_len];

    let arg_count = flags & 0x07;
    let serialized = (flags & 0x08) == 0x08;
    let sync_level = flags & 0xF0 >> 4;

    let term_list = match parse_term_list(&data[2 + pkg_len_len + name_len .. 1 + pkg_len]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 1 + pkg_len].to_vec()), 1 + pkg_len)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefMethod {
        name: name,
        method: Method {
            arg_count,
            serialized,
            sync_level,
            term_list
        }
    }, pkg_len + 1))
}

fn parse_def_mutex(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x01);

    let (name, name_len) = match parse_name_string(&data[2 ..]) {
        Ok(p) => p,
        Err(e) => return Err(e),
    };
    let flags = data[2 + name_len];
    let sync_level = flags & 0x0F;

    Ok((NamedObj::DefMutex {name, sync_level}, name_len + 3))
}

fn parse_def_power_res(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x84);

    let (pkg_len, pkg_len_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_len_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_len].to_vec()), 2 + pkg_len)),
        Err(e) => return Err(e)
    };

    let system_level = data[2 + pkg_len_len + name_len];
    let resource_order: u16 = (data[3 + pkg_len_len + name_len] as u16) +
        ((data[4 + pkg_len_len + name_len] as u16) << 8);

    let obj_list = match parse_object_list(&data[5 + pkg_len_len + name_len .. 2 + pkg_len]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_len].to_vec()), 2 + pkg_len)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefPowerRes {name, system_level, resource_order, obj_list}, 2 + pkg_len))
}

fn parse_def_processor(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x83);

    let (pkg_len, pkg_len_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_len_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_len].to_vec()), 2 + pkg_len)),
        Err(e) => return Err(e)
    };

    let proc_id = data[2 + pkg_len_len + name_len];
    let p_blk_addr: u32 = (data[3 + pkg_len_len + name_len] as u32) +
        ((data[4 + pkg_len_len + name_len] as u32) << 8) +
        ((data[5 + pkg_len_len + name_len] as u32) << 16) +
        ((data[6 + pkg_len_len + name_len] as u32) << 24);
    let p_blk_len = data[7 + pkg_len_len + name_len];

    let obj_list = match parse_object_list(&data[8 + pkg_len_len + name_len .. 2 + pkg_len]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_len].to_vec()), 2 + pkg_len)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefProcessor {name, proc_id, p_blk_addr, p_blk_len, obj_list}, 2 + pkg_len))
}

fn parse_def_thermal_zone(data: &[u8]) -> Result<(NamedObj, usize), AmlInternalError> {
    parser_opcode_extended!(data, 0x85);

    let (pkg_len, pkg_len_len) = parse_pkg_length(&data[2..])?;
    let (name, name_len) = match parse_name_string(&data[2 + pkg_len_len..]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_len].to_vec()), 2 + pkg_len)),
        Err(e) => return Err(e)
    };

    let obj_list = match parse_object_list(&data[2 + pkg_len_len + name_len .. 2 + pkg_len]) {
        Ok(p) => p,
        Err(AmlInternalError::AmlDeferredLoad) =>
            return Ok((NamedObj::DeferredLoad(data[0 .. 2 + pkg_len].to_vec()), 2 + pkg_len)),
        Err(e) => return Err(e)
    };

    Ok((NamedObj::DefThermalZone {name, obj_list}, 2 + pkg_len))
}
