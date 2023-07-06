use x86::controlregs::Cr4;
use x86::cpuid::ExtendedFeatures;

pub unsafe fn init() {
    let has_ext_feat = |feat: fn(ExtendedFeatures) -> bool| crate::cpuid::cpuid_always().get_extended_feature_info().map_or(false, feat);

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
    if has_ext_feat(|feat| feat.has_smap()) && cfg!(feature = "x86_smap") {
        // SMAP (Supervisor-Mode Access Prevention) forbids the kernel from accessing any
        // userspace-accessible pages, with the necessary exception of RFLAGS.AC = 1. This limits
        // user-memory accesses to the UserSlice wrapper, so that no code outside of usercopy
        // functions can be accidentally accessed by the kernel.
        x86::controlregs::cr4_write(x86::controlregs::cr4() | Cr4::CR4_ENABLE_SMAP);
        // Clear CLAC in (the probably unlikely) case the bootloader set it earlier.
        x86::bits64::rflags::clac();
    }
}
