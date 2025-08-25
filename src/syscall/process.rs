use alloc::{sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize};

use rmm::Arch;
use spin::RwLock;
use strum::IntoEnumIterator;
use syscall::data::GlobalSchemes;

use crate::{
    context::{
        file::{FileDescription, FileDescriptor, InternalFlags},
        memory::{AddrSpace, Grant, PageSpan},
        ContextRef,
    },
    event,
    syscall::{
        flag::{O_CREAT, O_RDWR},
        EventFlags,
    },
};

use crate::{
    context,
    context::context::FdTbl,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    scheme::SchemeExt,
    syscall::{error::*, flag::MapFlags},
    Bootstrap, CurrentRmmArch,
};

use super::usercopy::UserSliceWo;

pub fn exit_this_context(excp: Option<syscall::Exception>) -> ! {
    let mut close_files;
    let addrspace_opt;

    let context_lock = context::current();
    {
        let mut context = context_lock.write();
        close_files = Arc::try_unwrap(mem::take(&mut context.files))
            .map_or_else(|_| FdTbl::new(), RwLock::into_inner);
        addrspace_opt = context
            .set_addr_space(None)
            .and_then(|a| Arc::try_unwrap(a).ok());
        drop(context.syscall_head.take());
        drop(context.syscall_tail.take());
    }

    // Files must be closed while context is valid so that messages can be passed
    close_files.force_close_all();
    drop(addrspace_opt);
    // TODO: Should status == Status::HardBlocked be handled differently?
    let owner = {
        let mut guard = context_lock.write();
        guard.status = context::Status::Dead { excp };
        guard.owner_proc_id
    };
    if let Some(owner) = owner {
        let _ = event::trigger(
            GlobalSchemes::Proc.scheme_id(),
            owner.get(),
            EventFlags::EVENT_READ,
        );
    }
    let _ = context::contexts_mut().remove(&ContextRef(context_lock));
    context::switch();
    unreachable!();
}

pub fn mprotect(address: usize, size: usize, flags: MapFlags) -> Result<()> {
    // println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    let span = PageSpan::validate_nonempty(VirtualAddress::new(address), size)
        .ok_or(Error::new(EINVAL))?;

    AddrSpace::current()?.mprotect(span, flags)
}

pub unsafe fn usermode_bootstrap(bootstrap: &Bootstrap) {
    assert_ne!(bootstrap.page_count, 0);

    {
        let addr_space = Arc::clone(
            context::current()
                .read()
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

        const KERNEL_SCHEMES_BASE: usize =
            crate::USER_END_OFFSET - syscall::BOOTSTRAP_STACK_SIZE - PAGE_SIZE;
        const KERNEL_SCHEMES_INFO_PAGE_COUNT: usize = 1;
        const KERNEL_SCHEMES_COUNT: usize = core::mem::variant_count::<GlobalSchemes>();

        let mut kernel_schemes_infos =
            [syscall::data::KernelSchemeInfo::default(); KERNEL_SCHEMES_COUNT];
        for (i, scheme) in GlobalSchemes::iter().enumerate() {
            kernel_schemes_infos[i] = syscall::data::KernelSchemeInfo {
                scheme_id: scheme.scheme_id().get() as u8,
                fd: {
                    let cap_fd = match scheme.as_scheme().open_capability() {
                        Ok(fd) => fd,
                        Err(_) => usize::MAX,
                    };
                    context::current()
                        .write()
                        .add_file_min(
                            FileDescriptor {
                                description: Arc::new(RwLock::new(FileDescription {
                                    scheme: scheme.scheme_id(),
                                    number: cap_fd,
                                    offset: 0,
                                    flags: (O_CREAT | O_RDWR) as u32,
                                    internal_flags: InternalFlags::empty(),
                                })),
                                cloexec: false,
                            },
                            syscall::flag::UPPER_FDTBL_TAG + scheme.scheme_id().get(),
                        )
                        .expect("failed to create pipe scheme")
                        .get()
                },
            };
        }

        let kernel_schemes_info_page = addr_space
            .acquire_write()
            .mmap(
                &addr_space,
                Some(Page::containing_address(VirtualAddress::new(
                    KERNEL_SCHEMES_BASE,
                ))),
                NonZeroUsize::new(KERNEL_SCHEMES_INFO_PAGE_COUNT).unwrap(),
                MapFlags::MAP_FIXED_NOREPLACE | MapFlags::PROT_READ | MapFlags::PROT_WRITE,
                &mut Vec::new(),
                |page, flags, mapper, flusher| {
                    let shared = false;
                    Ok(Grant::zeroed(
                        PageSpan::new(page, KERNEL_SCHEMES_INFO_PAGE_COUNT),
                        flags,
                        mapper,
                        flusher,
                        shared,
                    )?)
                },
            )
            .expect("Failed to allocate kernel scheme info page");

        const HEADER_SIZE: usize = mem::size_of::<usize>();
        UserSliceWo::new(kernel_schemes_info_page.start_address().data(), HEADER_SIZE)
            .expect("failed to create kernel schemes header user slice")
            .copy_common_bytes_from_slice(&KERNEL_SCHEMES_COUNT.to_ne_bytes())
            .expect("failed to copy kernel schemes count");
        let info_bytes = unsafe {
            core::slice::from_raw_parts(
                kernel_schemes_infos.as_ptr() as *const u8,
                KERNEL_SCHEMES_COUNT * mem::size_of::<syscall::data::KernelSchemeInfo>(),
            )
        };
        UserSliceWo::new(
            kernel_schemes_info_page.start_address().data() + HEADER_SIZE,
            KERNEL_SCHEMES_COUNT * mem::size_of::<syscall::data::KernelSchemeInfo>(),
        )
        .expect("failed to create kernel schemes info user slice")
        .copy_common_bytes_from_slice(info_bytes)
        .expect("failed to copy kernel schemes info");

        addr_space.mprotect(
            PageSpan::new(
                Page::containing_address(VirtualAddress::new(KERNEL_SCHEMES_BASE)),
                KERNEL_SCHEMES_INFO_PAGE_COUNT,
            ),
            MapFlags::PROT_READ,
        )?;
    }

    let bootstrap_slice = unsafe { bootstrap_mem(bootstrap) };
    UserSliceWo::new(PAGE_SIZE, bootstrap.page_count * PAGE_SIZE)
        .expect("failed to create bootstrap user slice")
        .copy_from_slice(bootstrap_slice)
        .expect("failed to copy memory to bootstrap");

    let bootstrap_entry = u64::from_le_bytes(bootstrap_slice[0x1a..0x22].try_into().unwrap());
    log::info!("Bootstrap entry point: {:X}", bootstrap_entry);
    assert_ne!(bootstrap_entry, 0);
    println!("\n");

    // Start in a minimal environment without any stack.

    match context::current()
        .write()
        .regs_mut()
        .expect("bootstrap needs registers to be available")
    {
        ref mut regs => {
            regs.init();
            regs.set_instr_pointer(bootstrap_entry.try_into().unwrap());
        }
    }
}

pub unsafe fn bootstrap_mem(bootstrap: &crate::Bootstrap) -> &'static [u8] {
    core::slice::from_raw_parts(
        CurrentRmmArch::phys_to_virt(bootstrap.base.base()).data() as *const u8,
        bootstrap.page_count * PAGE_SIZE,
    )
}
