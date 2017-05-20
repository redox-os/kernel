use collections::vec::Vec;

use super::sdt::Sdt;

pub fn parse_aml_table(data: &[u8]) -> Option<Vec<u8>> {
    parse_term_list(data)
}

fn parse_term_list(data: &[u8]) -> Option<Vec<u8>> {
    let mut terms: Vec<u8> = vec!();
    let mut current_offset: usize = 0;

    while current_offset < data.len() {
        if let Some((namespace_modifier, length)) = parse_namespace_modifier(data) {
            terms.push(namespace_modifier);
            current_offset += length;
        } else if let Some((named_obj, length)) = parse_named_obj(data) {
            terms.push(named_obj);
            current_offset += length;
        } else if let Some((type1_opcode, length)) = parse_type1_opcode(data) {
            terms.push(type1_opcode);
            current_offset += length;
        } else if let Some((type2_opcode, length)) = parse_type2_opcode(data) {
            terms.push(type2_opcode);
            current_offset += length;
        } else {
            // return None;
            break;
        }
    }

    Some(terms)
}

fn parse_namespace_modifier(data: &[u8]) -> Option<(u8, usize)> {
    None
}

fn parse_named_obj(data: &[u8]) -> Option<(u8, usize)> {
    None
}

fn parse_type1_opcode(data: &[u8]) -> Option<(u8, usize)> {
    None
}

fn parse_type2_opcode(data: &[u8]) -> Option<(u8, usize)> {
    None
}
