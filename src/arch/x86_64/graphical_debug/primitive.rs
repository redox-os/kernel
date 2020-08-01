#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub unsafe fn fast_copy(dst: *mut u8, src: *const u8, len: usize) {
    asm!("cld
        rep movsb",
         in("rdi") (dst as usize),
         in("rsi") (src as usize),
         in("rcx") len,
         out("cc") _,
         out("rdi") _,
         out("rsi") _,
         out("rcx") _,
    );
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub unsafe fn fast_set32(dst: *mut u32, src: u32, len: usize) {
    asm!("cld
        rep stosd",
         in("rdi") (dst as usize),
         in("eax") src,
         in("rcx") len,
         out("cc") _,
         out("rdi") _,
         out("rcx") _,
    );
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cold]
pub unsafe fn fast_set64(dst: *mut u64, src: u64, len: usize) {
    asm!("cld
        rep stosq"
         in("rdi") (dst as usize),
         in("rax") src,
         in("rcx") len,
         out("cc") _,
         out("rdi") _,
         out("rcx") _,
    );
}
