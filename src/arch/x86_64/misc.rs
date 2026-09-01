use x86::controlregs::Cr4;

use crate::{
    arch::cpuid::{cpuid, has_ext_feat},
    cpu_set::LogicalCpuId,
};

pub unsafe fn init(cpu_id: LogicalCpuId) {
    unsafe {
        if has_ext_feat(|feat| feat.has_umip()) {
            // UMIP (UserMode Instruction Prevention) forbids userspace from calling SGDT, SIDT, SLDT,
            // SMSW and STR. KASLR is currently not implemented, but this protects against leaking
            // addresses.
            x86::controlregs::cr4_write(x86::controlregs::cr4() | Cr4::CR4_ENABLE_UMIP);
        }
        if has_ext_feat(|feat| feat.has_smep()) {
            // SMEP (Supervisor-Mode Execution Prevention) forbids the kernel from executing
            // instruction on any page marked "userspace-accessible". This improves security for
            // obvious reasons.
            x86::controlregs::cr4_write(x86::controlregs::cr4() | Cr4::CR4_ENABLE_SMEP);
        }

        if let Some(feats) = cpuid().get_extended_processor_and_feature_identifiers()
            && feats.has_rdtscp()
        {
            // TSC_AUX is useful as it allows both the userspace and kernel to relatively quickly
            // read the processor ID, e.g. with RDPID and RDTSCP.
            x86::msr::wrmsr(x86::msr::IA32_TSC_AUX, cpu_id.get().into());
        }

        // Allows reading performance counters in userspace. This in itself should be harmless, as
        // the counters won't do anything unless explicitly configured through the MSRs.
        if cfg!(feature = "profiling") {
            x86::controlregs::cr4_write(x86::controlregs::cr4() | Cr4::CR4_ENABLE_PPMC);
        }
    }
}

unsafe extern "C" {
    pub fn __the_wrapped_rdmsr_instr();
    pub fn __the_wrapped_wrmsr_instr();
}
#[derive(Debug)]
pub struct MsrFault;

/// Reads an MSR "safely", i.e. handling #GP if the register does not exist or fails to be read
/// from another reason. This can still have side effects that may completely corrupt the kernel
/// (more so for wrmsr), but which is outside Rust's safety model just like safe Rust can open
/// `/dev/mem` on userspace Linux. Only privileged userspace processes should ever be granted a
/// capability to read MSRs.
#[allow(named_asm_labels)]
pub fn rdmsr_safe(reg: u32) -> Result<u64, MsrFault> {
    let failed: u32;
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("
            .globl __the_wrapped_rdmsr_instr
__the_wrapped_rdmsr_instr:
            rdmsr
            ",
            // protection fault handler sets esi if the error occurred at either of these
            // instruction offsets.
            inout("esi") 0 => failed,
            in("ecx") reg,
            out("eax") lo,
            out("edx") hi,
        );
    }
    if failed != 0 {
        return Err(MsrFault);
    }
    Ok(u64::from(lo) | (u64::from(hi) << 32))
}
/// Writes an MSR "safely", handling #GP.
#[allow(named_asm_labels)]
pub fn wrmsr_safe(reg: u32, value: u64) -> Result<(), MsrFault> {
    let failed: u32;
    unsafe {
        core::arch::asm!("
            .globl __the_wrapped_wrmsr_instr
__the_wrapped_wrmsr_instr:
            wrmsr
            ",
            // protection fault handler sets esi if the error occurred at either of these
            // instruction offsets.
            inout("esi") 0 => failed,
            in("ecx") reg,
            in("eax") value & 0xffff_ffff,
            in("edx") value >> 32,
        );
    }
    if failed != 0 {
        return Err(MsrFault);
    }
    Ok(())
}
