use alloc::{sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize};

use rmm::Arch;
use spin::RwLock;

use crate::{
    context::{
        context::SyscallFrame,
        memory::{AddrSpace, Grant, PageSpan},
        ContextRef,
    },
    event,
    scheme::GlobalSchemes,
    sync::CleanLockToken,
    syscall::EventFlags,
};

use crate::{
    context,
    context::context::FdTbl,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    syscall::{error::*, flag::MapFlags},
    Bootstrap, CurrentRmmArch,
};

use super::usercopy::UserSliceWo;

pub fn exit_this_context(excp: Option<syscall::Exception>, token: &mut CleanLockToken) -> ! {
    let mut close_files;
    let addrspace_opt;

    let context_lock = context::current();
    {
        let mut context = context_lock.write(token.token());
        close_files = Arc::try_unwrap(mem::take(&mut context.files))
            .map_or_else(|_| FdTbl::new(), RwLock::into_inner);
        addrspace_opt = context
            .set_addr_space(None)
            .and_then(|a| Arc::try_unwrap(a).ok());
        drop(mem::replace(&mut context.syscall_head, SyscallFrame::Dummy));
        drop(mem::replace(&mut context.syscall_tail, SyscallFrame::Dummy));
    }

    // Files must be closed while context is valid so that messages can be passed
    close_files.force_close_all(token);
    drop(addrspace_opt);
    // TODO: Should status == Status::HardBlocked be handled differently?
    let owner = {
        let mut guard = context_lock.write(token.token());
        guard.status = context::Status::Dead { excp };
        guard.owner_proc_id
    };
    if let Some(owner) = owner {
        event::trigger(
            GlobalSchemes::Proc.scheme_id(),
            owner.get(),
            EventFlags::EVENT_READ,
        );
    }
    {
        let _ = context::contexts_mut(token.token()).remove(&ContextRef(context_lock));
    }
    context::switch(token);
    unreachable!();
}

pub fn mprotect(address: usize, size: usize, flags: MapFlags) -> Result<()> {
    // println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    let span = PageSpan::validate_nonempty(VirtualAddress::new(address), size)
        .ok_or(Error::new(EINVAL))?;

    AddrSpace::current()?.mprotect(span, flags)
}

pub unsafe fn usermode_bootstrap(bootstrap: &Bootstrap, token: &mut CleanLockToken) {
    assert_ne!(bootstrap.page_count, 0);

    {
        let addr_space = Arc::clone(
            context::current()
                .read(token.token())
                .addr_space()
                .expect("expected bootstrap context to have an address space"),
        );

        let base = Page::containing_address(VirtualAddress::new(PAGE_SIZE));
        let flags = MapFlags::MAP_FIXED_NOREPLACE
            | MapFlags::PROT_EXEC
            | MapFlags::PROT_READ
            | MapFlags::PROT_WRITE;

        let page_count =
            NonZeroUsize::new(bootstrap.page_count).expect("bootstrap contained no pages!");

        let _base_page = addr_space
            .acquire_write()
            .mmap(
                &addr_space,
                Some(base),
                page_count,
                flags,
                &mut Vec::new(),
                |page, flags, mapper, flusher| {
                    let shared = false;
                    Ok(Grant::zeroed(
                        PageSpan::new(page, bootstrap.page_count),
                        flags,
                        mapper,
                        flusher,
                        shared,
                    )?)
                },
            )
            .expect("Failed to allocate bootstrap pages");
    }

    let bootstrap_slice = unsafe { bootstrap_mem(bootstrap) };
    UserSliceWo::new(PAGE_SIZE, bootstrap.page_count * PAGE_SIZE)
        .expect("failed to create bootstrap user slice")
        .copy_from_slice(bootstrap_slice)
        .expect("failed to copy memory to bootstrap");

    let bootstrap_entry = u64::from_le_bytes(bootstrap_slice[0x1a..0x22].try_into().unwrap());
    info!("Bootstrap entry point: {:X}", bootstrap_entry);
    assert_ne!(bootstrap_entry, 0);
    println!("\n");

    // Start in a minimal environment without any stack.

    let ctx = context::current();
    let mut lock = ctx.write(token.token());
    let regs = &mut lock
        .regs_mut()
        .expect("bootstrap needs registers to be available");
    {
        regs.init();
        regs.set_instr_pointer(bootstrap_entry.try_into().unwrap());
    }
}

pub unsafe fn bootstrap_mem(bootstrap: &crate::Bootstrap) -> &'static [u8] {
    unsafe {
        core::slice::from_raw_parts(
            CurrentRmmArch::phys_to_virt(bootstrap.base.base()).data() as *const u8,
            bootstrap.page_count * PAGE_SIZE,
        )
    }
}
