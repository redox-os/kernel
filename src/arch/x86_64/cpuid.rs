use raw_cpuid::{ExtendedFeatures, FeatureInfo};

pub use crate::arch::x86_shared::cpuid::*;

pub fn feature_info() -> FeatureInfo {
    cpuid()
        .get_feature_info()
        .expect("x86_64 requires CPUID leaf=0x01 to be present")
}

pub fn has_ext_feat(feat: impl FnOnce(ExtendedFeatures) -> bool) -> bool {
    cpuid().get_extended_feature_info().map_or(false, feat)
}
