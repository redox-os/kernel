use core::ptr;

use memory::Frame;
use paging::ActivePageTable;
use paging::entry::EntryFlags;

#[cfg(feature = "pti")]
#[thread_local]
pub static mut PTI_CPU_STACK: [u8; 256] = [0; 256];

#[cfg(feature = "pti")]
#[thread_local]
pub static mut PTI_CONTEXT_STACK: usize = 0;

#[cfg(feature = "pti")]
#[inline(never)]
#[naked]
unsafe fn switch_stack(old: usize, new: usize) {
    asm!("xchg bx, bx" : : : : "intel", "volatile");

    let old_rsp: usize;
    let old_rbp: usize;
    asm!("" : "={rsp}"(old_rsp), "={rbp}"(old_rbp) : : : "intel", "volatile");

    let offset_rsp = old - old_rsp;
    let offset_rbp = old - old_rbp;

    let new_rsp = new - offset_rsp;
    let new_rbp = new - offset_rbp;

    ptr::copy_nonoverlapping(
        old_rsp as *const u8,
        new_rsp as *mut u8,
        offset_rsp
    );

    asm!("xchg bx, bx" : : : : "intel", "volatile");

    asm!("" : : "{rsp}"(new_rsp), "{rbp}"(new_rbp) : : "intel", "volatile");
}

#[cfg(feature = "pti")]
#[inline(never)]
#[naked]
pub unsafe fn map() {
    asm!("xchg bx, bx" : : : : "intel", "volatile");

    // {
    //     let mut active_table = unsafe { ActivePageTable::new() };
    //
    //     // Map kernel heap
    //     let address = active_table.p4()[::KERNEL_HEAP_PML4].address();
    //     let frame = Frame::containing_address(address);
    //     let mut flags = active_table.p4()[::KERNEL_HEAP_PML4].flags();
    //     flags.remove(EntryFlags::PRESENT);
    //     active_table.p4_mut()[::KERNEL_HEAP_PML4].set(frame, flags);
    //
    //     // Reload page tables
    //     active_table.flush_all();
    // }

    // Switch to per-context stack
    switch_stack(PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len(), PTI_CONTEXT_STACK);
}

#[cfg(feature = "pti")]
#[inline(never)]
#[naked]
pub unsafe fn unmap() {
    asm!("xchg bx, bx" : : : : "intel", "volatile");

    // Switch to per-CPU stack
    switch_stack(PTI_CONTEXT_STACK, PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len());

    // {
    //     let mut active_table = unsafe { ActivePageTable::new() };
    //
    //     // Unmap kernel heap
    //     let address = active_table.p4()[::KERNEL_HEAP_PML4].address();
    //     let frame = Frame::containing_address(address);
    //     let mut flags = active_table.p4()[::KERNEL_HEAP_PML4].flags();
    //     flags.insert(EntryFlags::PRESENT);
    //     active_table.p4_mut()[::KERNEL_HEAP_PML4].set(frame, flags);
    //
    //     // Reload page tables
    //     active_table.flush_all();
    // }
}

#[cfg(not(feature = "pti"))]
#[inline(always)]
pub unsafe fn map() {}

#[cfg(not(feature = "pti"))]
#[inline(always)]
pub unsafe fn unmap() {}
