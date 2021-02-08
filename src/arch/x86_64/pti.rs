#[cfg(feature = "pti")]
use core::ptr;

#[cfg(feature = "pti")]
use crate::memory::Frame;
#[cfg(feature = "pti")]
use crate::paging::ActivePageTable;
#[cfg(feature = "pti")]
use crate::paging::entry::EntryFlags;

#[cfg(feature = "pti")]
#[thread_local]
pub static mut PTI_CPU_STACK: [u8; 256] = [0; 256];

#[cfg(feature = "pti")]
#[thread_local]
pub static mut PTI_CONTEXT_STACK: usize = 0;

#[cfg(feature = "pti")]
#[inline(always)]
unsafe fn switch_stack(old: usize, new: usize) {
    let old_rsp: usize;
    asm!("", out("rsp") old_rsp);

    let offset_rsp = old - old_rsp;

    let new_rsp = new - offset_rsp;

    ptr::copy_nonoverlapping(
        old_rsp as *const u8,
        new_rsp as *mut u8,
        offset_rsp
    );

    asm!("", out("rsp") new_rsp);
}

#[cfg(feature = "pti")]
#[inline(always)]
pub unsafe fn map() {
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
#[inline(always)]
pub unsafe extern "C" fn unmap() {
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
pub unsafe extern "C" fn unmap() {}
