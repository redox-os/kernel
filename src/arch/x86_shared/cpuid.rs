use raw_cpuid::{CpuId, CpuIdResult};

pub fn cpuid() -> CpuId {
    // FIXME check for cpuid availability during early boot and error out if it doesn't exist.
    CpuId::with_cpuid_fn(|a, c| {
        #[cfg(target_arch = "x86")]
        let result = unsafe { core::arch::x86::__cpuid_count(a, c) };
        #[cfg(target_arch = "x86_64")]
        let result = unsafe { core::arch::x86_64::__cpuid_count(a, c) };
        CpuIdResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        }
    })
}
