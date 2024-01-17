use raw_cpuid::{CpuId, CpuIdResult, ExtendedFeatures, FeatureInfo};

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

pub fn feature_info() -> FeatureInfo {
    cpuid_always()
        .get_feature_info()
        .expect("x86_64 requires CPUID leaf=0x01 to be present")
}

pub fn has_ext_feat(feat: impl FnOnce(ExtendedFeatures) -> bool) -> bool {
    cpuid_always()
        .get_extended_feature_info()
        .map_or(false, feat)
}
