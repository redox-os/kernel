use alloc::{sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize};

use rmm::Arch;
use spin::RwLock;
use syscall::data::GlobalSchemes;

use crate::{
    context::{
        context::SyscallFrame,
        file::{FileDescription, FileDescriptor, InternalFlags},
        memory::{AddrSpace, Grant, PageSpan},
        ContextRef,
    },
    event,
    sync::CleanLockToken,
    syscall::flag::{EventFlags, O_CREAT, O_RDWR},
};

use crate::{
    context,
    context::context::FdTbl,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    scheme::{
        KernelScheme, SchemeExt, SchemeId, SchemeList, ALL_KERNEL_SCHEMES, KERNEL_SCHEMES_COUNT,
    },
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

const KERNEL_METADATA_BASE: usize = crate::USER_END_OFFSET - syscall::KERNEL_METADATA_SIZE;
const KERNEL_METADATA_PAGE_COUNT: usize = syscall::KERNEL_METADATA_SIZE / PAGE_SIZE + {
    if syscall::KERNEL_METADATA_SIZE.is_multiple_of(PAGE_SIZE) {
        0
    } else {
        1
    }
};

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

        // Insert kernel schemes root capabilities.
        let mut kernel_schemes_infos =
            [syscall::data::KernelSchemeInfo::default(); KERNEL_SCHEMES_COUNT];
        for (i, scheme) in ALL_KERNEL_SCHEMES.iter().enumerate() {
            if let Some(inner) = kernel_schemes_infos.get_mut(i) {
                inner.scheme_id = scheme.scheme_id().get() as u8;
                inner.fd = {
                    let cap_fd = match scheme.as_scheme().scheme_root(token) {
                        Ok(fd) => fd,
                        Err(_) => usize::MAX,
                    };
                    insert_fd(
                        scheme.scheme_id(),
                        cap_fd,
                        matches!(scheme, GlobalSchemes::Proc),
                        token,
                    )
                };
            }
        }
        // Insert a scheme creation capability for the usermode bootstrap.
        let scheme_creation_cap = {
            // First, get the scheme root to initialize the schemelist.
            let cap_fd = match &SchemeList.scheme_root(token) {
                Ok(fd) => *fd,
                Err(_) => usize::MAX,
            };
            // Second, retrieve the scheme ID.
            let scheme_id = &SchemeList.id();
            insert_fd(*scheme_id, cap_fd, false, token)
        };

        let kernel_schemes_info_page = addr_space
            .acquire_write()
            .mmap(
                &addr_space,
                Some(Page::containing_address(VirtualAddress::new(
                    KERNEL_METADATA_BASE,
                ))),
                NonZeroUsize::new(KERNEL_METADATA_PAGE_COUNT).unwrap(),
                MapFlags::MAP_FIXED_NOREPLACE | MapFlags::PROT_READ | MapFlags::PROT_WRITE,
                &mut Vec::new(),
                |page, flags, mapper, flusher| {
                    let shared = false;
                    Ok(Grant::zeroed(
                        PageSpan::new(page, KERNEL_METADATA_PAGE_COUNT),
                        flags,
                        mapper,
                        flusher,
                        shared,
                    )?)
                },
            )
            .expect("Failed to allocate kernel scheme info page");

        let mut cursor = kernel_schemes_info_page.start_address().data();
        const HEADER_SIZE: usize = mem::size_of::<usize>();
        UserSliceWo::new(cursor, HEADER_SIZE)
            .expect("failed to create kernel schemes header user slice")
            .copy_common_bytes_from_slice(&KERNEL_SCHEMES_COUNT.to_ne_bytes())
            .expect("failed to copy kernel schemes count");
        cursor += HEADER_SIZE;
        let info_bytes = unsafe {
            core::slice::from_raw_parts(
                kernel_schemes_infos.as_ptr() as *const u8,
                KERNEL_SCHEMES_COUNT * mem::size_of::<syscall::data::KernelSchemeInfo>(),
            )
        };
        UserSliceWo::new(
            cursor,
            KERNEL_SCHEMES_COUNT * mem::size_of::<syscall::data::KernelSchemeInfo>(),
        )
        .expect("failed to create kernel schemes info user slice")
        .copy_common_bytes_from_slice(info_bytes)
        .expect("failed to copy kernel schemes info");
        cursor += KERNEL_SCHEMES_COUNT * mem::size_of::<syscall::data::KernelSchemeInfo>();
        UserSliceWo::new(cursor, mem::size_of::<usize>())
            .expect("failed to create scheme creation cap user slice")
            .copy_common_bytes_from_slice(&scheme_creation_cap.to_ne_bytes())
            .expect("failed to copy scheme creation cap");

        mprotect(
            KERNEL_METADATA_BASE,
            KERNEL_METADATA_PAGE_COUNT * PAGE_SIZE,
            MapFlags::PROT_READ,
        )
        .expect("failed to mprotect kernel schemes info page");
    }

    let bootstrap_slice = unsafe { bootstrap_mem(bootstrap) };
    UserSliceWo::new(PAGE_SIZE, bootstrap.page_count * PAGE_SIZE)
        .expect("failed to create bootstrap user slice")
        .copy_from_slice(bootstrap_slice)
        .expect("failed to copy memory to bootstrap");

    let bootstrap_entry = u64::from_le_bytes(bootstrap_slice[0x1a..0x22].try_into().unwrap());
    debug!("Bootstrap entry point: {:X}", bootstrap_entry);
    assert_ne!(bootstrap_entry, 0);

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

unsafe fn bootstrap_mem(bootstrap: &crate::Bootstrap) -> &'static [u8] {
    unsafe {
        core::slice::from_raw_parts(
            CurrentRmmArch::phys_to_virt(bootstrap.base.base()).data() as *const u8,
            bootstrap.page_count * PAGE_SIZE,
        )
    }
}

fn insert_fd(scheme: SchemeId, number: usize, cloexec: bool, token: &mut CleanLockToken) -> usize {
    context::current()
        .write(token.token())
        .add_file_min(
            FileDescriptor {
                description: Arc::new(RwLock::new(FileDescription {
                    scheme,
                    number,
                    offset: 0,
                    flags: (O_CREAT | O_RDWR) as u32,
                    internal_flags: InternalFlags::empty(),
                })),
                cloexec,
            },
            syscall::flag::UPPER_FDTBL_TAG + scheme.get(),
        )
        .expect("failed to insert fd to current context")
        .get()
}
