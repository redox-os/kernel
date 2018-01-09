#[cfg(feature = "pti")]
#[inline(always)]
pub unsafe fn map() {
    let _cr3: usize;
    asm!("mov $0, cr3
          mov cr3, $0"
          : "=r"(_cr3) : : "memory" : "intel", "volatile");
}

#[cfg(feature = "pti")]
#[inline(always)]
pub unsafe fn unmap() {
    let _cr3: usize;
    asm!("mov $0, cr3
          mov cr3, $0"
          : "=r"(_cr3) : : "memory" : "intel", "volatile");
}

#[cfg(not(feature = "pti"))]
#[inline(always)]
pub unsafe fn map() {}

#[cfg(not(feature = "pti"))]
#[inline(always)]
pub unsafe fn unmap() {}
