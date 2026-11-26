use syscall::{schemev2::Opcode, CallFlags};

pub fn priority_allowed(opcode: Opcode, flags: CallFlags, euid: u32) -> bool {
    matches!(opcode, Opcode::Call) && flags.contains(CallFlags::PRIORITY) && euid == 0
}
