use core::{arch::asm, mem};

pub struct StackTrace {
    pub fp: usize,
    pub pc_ptr: *const usize,
}

impl StackTrace {
    #[inline(always)]
    pub unsafe fn start() -> Option<Self> {
        let fp: usize;
        asm!("mv {}, fp", out(reg) fp);

        let pc_ptr = fp.checked_sub(mem::size_of::<usize>())?;
        let fp = pc_ptr.checked_sub(mem::size_of::<usize>())?;
        Some(StackTrace {
            fp,
            pc_ptr: pc_ptr as *const usize,
        })
    }

    pub unsafe fn next(self) -> Option<Self> {
        let fp = *(self.fp as *const usize);
        let pc_ptr = fp.checked_sub(mem::size_of::<usize>())?;
        let fp = pc_ptr.checked_sub(mem::size_of::<usize>())?;
        Some(StackTrace {
            fp: fp,
            pc_ptr: pc_ptr as *const usize,
        })
    }
}
