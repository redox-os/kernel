#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub unsafe fn fast_copy(dst: *mut u8, src: *const u8, len: usize) {
    asm!("cld; rep movsb",
         in("rdi") dst as usize,
         in("rsi") src as usize,
         in("rcx") len,
         lateout("rdi") _,
         lateout("rsi") _,
         lateout("rcx") _,
    );
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub unsafe fn fast_set32(dst: *mut u32, src: u32, len: usize) {
    asm!("cld; rep stosd",
         in("rdi") dst as usize,
         in("eax") src,
         in("rcx") len,
         lateout("rdi") _,
         lateout("rcx") _,
    );
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub unsafe fn fast_set64(dst: *mut u64, src: u64, len: usize) {
    asm!("cld; rep stosq",
         in("rdi") dst as usize,
         in("rax") src,
         in("rcx") len,
         lateout("rdi") _,
         lateout("rcx") _,
    );
}
