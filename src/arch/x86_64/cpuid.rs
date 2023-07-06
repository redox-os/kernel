use raw_cpuid::{CpuId, CpuIdResult};

pub fn cpuid() -> Option<CpuId> {
    // CPUID is always available on x86_64 systems.
    Some(cpuid_always())
}
pub fn cpuid_always() -> CpuId {
    CpuId::with_cpuid_fn(|a, c| {
        let result = unsafe { core::arch::x86_64::__cpuid_count(a, c) };
        CpuIdResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        }
    })
}
