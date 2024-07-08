use x86::controlregs::Cr4;

use crate::{
    cpu_set::LogicalCpuId,
    cpuid::{cpuid, has_ext_feat},
};

pub unsafe fn init(cpu_id: LogicalCpuId) {
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
        x86::msr::wrmsr(x86::msr::IA32_TSC_AUX, cpu_id.get().into());
    }
}
