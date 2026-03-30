bitflags::bitflags! {
    pub struct EntryFlags: usize {
        const NO_CACHE =        1 << 4;
        const DEV_MEM =         0;
    }
}

/// Setup page attribute table
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn init_pat() {
    unsafe {
        let uncacheable = 0; // UC
        let write_combining = 1; // WC
        let write_through = 4; // WT
        let _write_protected = 5; // WP
        let write_back = 6; // WB
        let uncached = 7; // UC- (overridable by WC MTRR)

        let pat0 = write_back;
        let pat1 = write_through;
        let pat2 = uncached;
        let pat3 = uncacheable;

        let pat4 = write_combining;
        let pat5 = pat1;
        let pat6 = pat2;
        let pat7 = pat3;

        let msr = 631; // IA32_PAT
        let low = u32::from_be_bytes([pat3, pat2, pat1, pat0]);
        let high = u32::from_be_bytes([pat7, pat6, pat5, pat4]);
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high);
    }
}
