use core::mem;

pub struct StackTrace {
    pub fp: usize,
    pub pc_ptr: *const usize,
}

impl StackTrace {
    #[inline(always)]
    pub unsafe fn start() -> Option<Self> {
        let mut fp: usize;
        #[cfg(target_arch = "x86")]
        core::arch::asm!("mov {}, ebp", out(reg) fp);
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mov {}, rbp", out(reg) fp);
        let pc_ptr = fp.checked_add(mem::size_of::<usize>())?;
        Some(Self {
            fp,
            pc_ptr: pc_ptr as *const usize,
        })
    }

    pub unsafe fn next(self) -> Option<Self> {
        let fp = *(self.fp as *const usize);
        let pc_ptr = fp.checked_add(mem::size_of::<usize>())?;
        Some(Self {
            fp: fp,
            pc_ptr: pc_ptr as *const usize,
        })
    }
}
