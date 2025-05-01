use crate::{
    arch::paging::{Page, VirtualAddress},
    context::{
        self,
        context::{HardBlockedReason, SignalState},
        file::{FileDescriptor, InternalFlags},
        memory::{handle_notify_files, AddrSpace, AddrSpaceWrapper, Grant, PageSpan},
        Context, Status,
    },
    memory::{get_page_info, AddRefError, RefKind, PAGE_SIZE},
    ptrace,
    scheme::{self, FileHandle, KernelScheme},
    syscall::{
        data::{GrantDesc, Map, SetSighandlerData, Stat},
        error::*,
        flag::*,
        usercopy::{UserSliceRo, UserSliceRw, UserSliceWo},
        EnvRegisters, FloatRegisters, IntRegisters,
    },
};

use super::{CallerCtx, GlobalSchemes, KernelSchemes, OpenResult};
use ::syscall::{ProcSchemeAttrs, SigProcControl, Sigcontrol};
use alloc::{
    boxed::Box,
    collections::{btree_map::Entry, BTreeMap},
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use arrayvec::ArrayString;
use core::{
    mem::{self, size_of},
    num::NonZeroUsize,
    slice, str,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use spin::RwLock;
use spinning_top::RwSpinlock;

fn read_from(dst: UserSliceWo, src: &[u8], offset: u64) -> Result<usize> {
    let avail_src = usize::try_from(offset)
        .ok()
        .and_then(|o| src.get(o..))
        .unwrap_or(&[]);
    dst.copy_common_bytes_from_slice(avail_src)
}

fn try_stop_context<T>(
    context_ref: Arc<RwSpinlock<Context>>,
    callback: impl FnOnce(&mut Context) -> Result<T>,
) -> Result<T> {
    if context::is_current(&context_ref) {
        return callback(&mut *context_ref.write());
    }
    // Stop process
    let (prev_status, mut running) = {
        let mut context = context_ref.write();

        (
            core::mem::replace(
                &mut context.status,
                context::Status::HardBlocked {
                    reason: HardBlockedReason::NotYetStarted,
                },
            ),
            context.running,
        )
    };

    // Wait until stopped
    while running {
        context::switch();

        running = context_ref.read().running;
    }

    let mut context = context_ref.write();
    assert!(
        !context.running,
        "process can't have been restarted, we stopped it!"
    );

    let ret = callback(&mut *context);

    context.status = prev_status;

    ret
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegsKind {
    Float,
    Int,
    Env,
}
#[derive(Clone)]
enum ContextHandle {
    // Opened by the process manager, after which it is locked. This capability is used to open
    // Attr handles, to set ens/euid/egid/pid.
    Authority,
    Attr,

    Status {
        privileged: bool,
    }, // can write ContextVerb

    Regs(RegsKind),
    Sighandler,
    Start,
    NewFiletable {
        filetable: Arc<RwLock<Vec<Option<FileDescriptor>>>>,
        data: Box<[u8]>,
    },
    Filetable {
        filetable: Weak<RwLock<Vec<Option<FileDescriptor>>>>,
        data: Box<[u8]>,
    },
    AddrSpace {
        addrspace: Arc<AddrSpaceWrapper>,
    },
    CurrentAddrSpace,

    AwaitingAddrSpaceChange {
        new: Arc<AddrSpaceWrapper>,
        new_sp: usize,
        new_ip: usize,
    },

    CurrentFiletable,

    AwaitingFiletableChange {
        new_ft: Arc<RwLock<Vec<Option<FileDescriptor>>>>,
    },

    // TODO: Remove this once openat is implemented, or allow openat-via-dup via e.g. the top-level
    // directory.
    OpenViaDup,
    SchedAffinity,

    MmapMinAddr(Arc<AddrSpaceWrapper>),
}
#[derive(Clone)]
struct Handle {
    context: Arc<RwSpinlock<Context>>,
    kind: ContextHandle,
}
pub struct ProcScheme;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

#[cfg(feature = "debugger")]
#[allow(dead_code)]
pub fn foreach_addrsp(mut f: impl FnMut(&Arc<AddrSpaceWrapper>)) {
    for (_, handle) in HANDLES.read().iter() {
        let Handle {
            kind: ContextHandle::AddrSpace { addrspace, .. },
            ..
        } = handle
        else {
            continue;
        };
        f(&addrspace);
    }
}

fn new_handle((handle, fl): (Handle, InternalFlags)) -> Result<(usize, InternalFlags)> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let _ = HANDLES.write().insert(id, handle);
    Ok((id, fl))
}

enum OpenTy {
    Ctxt(Arc<RwSpinlock<Context>>),
    Auth,
}

impl ProcScheme {
    fn openat_context(
        &self,
        path: &str,
        context: Arc<RwSpinlock<Context>>,
    ) -> Result<Option<(ContextHandle, bool)>> {
        Ok(Some(match path {
            "addrspace" => (
                ContextHandle::AddrSpace {
                    addrspace: Arc::clone(
                        context
                            .read()
                            .addr_space()
                            .map_err(|_| Error::new(ENOENT))?,
                    ),
                },
                true,
            ),
            "filetable" => (
                ContextHandle::Filetable {
                    filetable: Arc::downgrade(&context.read().files),
                    data: Box::new([]),
                },
                true,
            ),
            "current-addrspace" => (ContextHandle::CurrentAddrSpace, false),
            "current-filetable" => (ContextHandle::CurrentFiletable, false),
            "regs/float" => (ContextHandle::Regs(RegsKind::Float), false),
            "regs/int" => (ContextHandle::Regs(RegsKind::Int), false),
            "regs/env" => (ContextHandle::Regs(RegsKind::Env), false),
            "sighandler" => (ContextHandle::Sighandler, false),
            "start" => (ContextHandle::Start, false),
            "open_via_dup" => (ContextHandle::OpenViaDup, false),
            "mmap-min-addr" => (
                ContextHandle::MmapMinAddr(Arc::clone(
                    context
                        .read()
                        .addr_space()
                        .map_err(|_| Error::new(ENOENT))?,
                )),
                false,
            ),
            "sched-affinity" => (ContextHandle::SchedAffinity, true),
            "status" => (ContextHandle::Status { privileged: false }, false),
            _ if path.starts_with("auth-") => {
                let nonprefix = &path["auth-".len()..];
                let next_dash = nonprefix.find('-').ok_or(Error::new(ENOENT))?;
                let auth_fd = nonprefix[..next_dash]
                    .parse::<usize>()
                    .map_err(|_| Error::new(ENOENT))?;
                let actual_name = &nonprefix[next_dash + 1..];

                let handle = match actual_name {
                    "attrs" => ContextHandle::Attr,
                    "status" => ContextHandle::Status { privileged: true },
                    _ => return Err(Error::new(ENOENT)),
                };

                let (hopefully_this_scheme, number) = extract_scheme_number(auth_fd)?;
                verify_scheme(hopefully_this_scheme)?;
                if !matches!(
                    HANDLES.read().get(&number).ok_or(Error::new(ENOENT))?.kind,
                    ContextHandle::Authority
                ) {
                    return Err(Error::new(ENOENT));
                }

                (handle, false)
            }
            _ => return Ok(None),
        }))
    }
    fn open_inner(
        &self,
        ty: OpenTy,
        operation_str: Option<&str>,
        flags: usize,
    ) -> Result<(usize, InternalFlags)> {
        let operation_name = operation_str.ok_or(Error::new(EINVAL))?;
        let (mut handle, positioned) = match ty {
            OpenTy::Ctxt(context) => {
                if let Some((kind, positioned)) =
                    self.openat_context(operation_name, Arc::clone(&context))?
                {
                    (Handle { context, kind }, positioned)
                } else {
                    return Err(Error::new(EINVAL));
                }
            }
            OpenTy::Auth => {
                extern "C" fn ret() {}
                let context = match operation_str.ok_or(Error::new(ENOENT))? {
                    "new-context" => {
                        let id = NonZeroUsize::new(NEXT_ID.fetch_add(1, Ordering::Relaxed))
                            .ok_or(Error::new(EMFILE))?;
                        let context = context::spawn(true, Some(id), ret)?;
                        HANDLES.write().insert(
                            id.get(),
                            Handle {
                                context,
                                kind: ContextHandle::OpenViaDup,
                            },
                        );
                        return Ok((id.get(), InternalFlags::empty()));
                    }
                    "cur-context" => context::current(),
                    _ => return Err(Error::new(ENOENT)),
                };

                (
                    Handle {
                        context,
                        kind: ContextHandle::OpenViaDup,
                    },
                    false,
                )
            }
        };

        {
            let filetable_opt = match handle {
                Handle {
                    kind:
                        ContextHandle::Filetable {
                            ref filetable,
                            ref mut data,
                        },
                    ..
                } => Some((filetable.upgrade().ok_or(Error::new(EOWNERDEAD))?, data)),
                Handle {
                    kind:
                        ContextHandle::NewFiletable {
                            ref filetable,
                            ref mut data,
                        },
                    ..
                } => Some((Arc::clone(filetable), data)),
                _ => None,
            };
            if let Some((filetable, data)) = filetable_opt {
                *data = {
                    use core::fmt::Write;

                    let mut data = String::new();
                    for index in filetable
                        .read()
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, val)| val.as_ref().map(|_| idx))
                    {
                        writeln!(data, "{}", index).unwrap();
                    }
                    data.into_bytes().into_boxed_slice()
                };
            }
        };

        let (id, int_fl) = new_handle((
            handle.clone(),
            if positioned {
                InternalFlags::POSITIONED
            } else {
                InternalFlags::empty()
            },
        ))?;

        Ok((id, int_fl))
    }
}

impl KernelScheme for ProcScheme {
    fn kopen(&self, path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        if path != "authority" {
            return Err(Error::new(ENOENT));
        }
        static LOCK: AtomicBool = AtomicBool::new(false);
        if LOCK.swap(true, Ordering::Relaxed) {
            return Err(Error::new(EEXIST));
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES.write().insert(
            id,
            Handle {
                // TODO: placeholder
                context: context::current(),
                kind: ContextHandle::Authority,
            },
        );
        Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        match handle {
            _ => Ok(EventFlags::empty()),
        }
    }

    fn close(&self, id: usize) -> Result<()> {
        let handle = HANDLES.write().remove(&id).ok_or(Error::new(EBADF))?;

        match handle {
            Handle {
                context,
                kind:
                    ContextHandle::AwaitingAddrSpaceChange {
                        new,
                        new_sp,
                        new_ip,
                    },
            } => {
                let _ = try_stop_context(context, |context: &mut Context| {
                    let regs = context.regs_mut().ok_or(Error::new(EBADFD))?;
                    regs.set_instr_pointer(new_ip);
                    regs.set_stack_pointer(new_sp);

                    Ok(context.set_addr_space(Some(new)))
                })?;
                let _ = ptrace::send_event(crate::syscall::ptrace_event!(
                    PTRACE_EVENT_ADDRSPACE_SWITCH,
                    0
                ));
            }
            Handle {
                kind: ContextHandle::AddrSpace { addrspace } | ContextHandle::MmapMinAddr(addrspace),
                ..
            } => drop(addrspace),

            Handle {
                kind: ContextHandle::AwaitingFiletableChange { new_ft },
                context,
            } => {
                context.write().files = new_ft;
            }
            _ => (),
        }
        Ok(())
    }
    fn kfmap(
        &self,
        id: usize,
        dst_addr_space: &Arc<AddrSpaceWrapper>,
        map: &crate::syscall::data::Map,
        consume: bool,
    ) -> Result<usize> {
        let handle = HANDLES.read().get(&id).ok_or(Error::new(EBADF))?.clone();
        let Handle { kind, ref context } = handle;

        match kind {
            ContextHandle::AddrSpace { ref addrspace } => {
                if Arc::ptr_eq(addrspace, dst_addr_space) {
                    return Err(Error::new(EBUSY));
                }

                let PageSpan {
                    base: requested_dst_page,
                    ..
                } = crate::syscall::validate_region(map.address, map.size)?;
                let src_span =
                    PageSpan::validate_nonempty(VirtualAddress::new(map.offset), map.size)
                        .ok_or(Error::new(EINVAL))?;

                let requested_dst_base = (map.address != 0).then_some(requested_dst_page);

                let mut src_addr_space = addrspace.acquire_write();

                let src_page_count = NonZeroUsize::new(src_span.count).ok_or(Error::new(EINVAL))?;

                let mut notify_files = Vec::new();

                // TODO: Validate flags
                let result_base = if consume {
                    dst_addr_space.r#move(
                        Some((&addrspace, &mut *src_addr_space)),
                        src_span,
                        requested_dst_base,
                        src_page_count.get(),
                        map.flags,
                        &mut notify_files,
                    )?
                } else {
                    let mut dst_addrsp_guard = dst_addr_space.acquire_write();
                    dst_addrsp_guard.mmap(
                        &dst_addr_space,
                        requested_dst_base,
                        src_page_count,
                        map.flags,
                        &mut notify_files,
                        |dst_page, _, dst_mapper, flusher| {
                            Ok(Grant::borrow(
                                Arc::clone(addrspace),
                                &mut *src_addr_space,
                                src_span.base,
                                dst_page,
                                src_span.count,
                                map.flags,
                                dst_mapper,
                                flusher,
                                true,
                                true,
                                false,
                            )?)
                        },
                    )?
                };

                handle_notify_files(notify_files);

                Ok(result_base.start_address().data())
            }
            ContextHandle::Sighandler => {
                let context = context.read();
                let sig = context.sig.as_ref().ok_or(Error::new(EBADF))?;
                let frame = match map.offset {
                    // tctl
                    0 => &sig.thread_control,
                    // pctl
                    PAGE_SIZE => &sig.proc_control,
                    _ => return Err(Error::new(EINVAL)),
                };
                let info = get_page_info(frame.get()).ok_or(Error::new(EBADFD))?;
                match info.add_ref(RefKind::Shared) {
                    Ok(()) => (),
                    Err(AddRefError::RcOverflow) => return Err(Error::new(ENOMEM)),
                    Err(AddRefError::CowToShared) => unreachable!("cannot be CoW since it's a kernel RaiiFrame that at some point was made Shared"),
                    Err(AddRefError::SharedToCow) => unreachable!("wasn't requested"),
                }
                // TODO: Allocated or AllocatedShared?
                let addrsp = AddrSpace::current()?;
                let page = addrsp.acquire_write().mmap(
                    &addrsp,
                    None,
                    NonZeroUsize::new(1).unwrap(),
                    MapFlags::PROT_READ | MapFlags::PROT_WRITE,
                    &mut Vec::new(),
                    |page, flags, mapper, flusher| {
                        Grant::allocated_shared_one_page(
                            frame.get(),
                            page,
                            flags,
                            mapper,
                            flusher,
                            false,
                        )
                    },
                )?;
                Ok(page.start_address().data())
            }
            _ => Err(Error::new(EBADF)),
        }
    }
    fn kreadoff(
        &self,
        id: usize,
        buf: UserSliceWo,
        offset: u64,
        read_flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let handle = {
            let handles = HANDLES.read();
            handles.get(&id).ok_or(Error::new(EBADF))?.clone()
        };

        match handle {
            Handle { context, kind } => kind.kreadoff(id, context, buf, offset),
        }
    }
    fn kcall(
        &self,
        id: usize,
        _payload: UserSliceRw,
        _flags: CallFlags,
        metadata: &[u64],
    ) -> Result<usize> {
        // TODO: simplify
        let handle = {
            let mut handles = HANDLES.write();
            let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let ContextHandle::OpenViaDup = handle.kind else {
            return Err(Error::new(EBADF));
        };

        let verb: u8 = (*metadata.get(0).ok_or(Error::new(EINVAL))?)
            .try_into()
            .map_err(|_| Error::new(EINVAL))?;
        let verb = ProcSchemeVerb::try_from_raw(verb).ok_or(Error::new(EINVAL))?;

        match verb {
            ProcSchemeVerb::Iopl => context::current().write().set_userspace_io_allowed(true),
        }
        Ok(0)
    }
    fn kwriteoff(
        &self,
        id: usize,
        buf: UserSliceRo,
        _offset: u64,
        _fcntl_flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        // TODO: offset

        // Don't hold a global lock during the context switch later on
        let handle = {
            let mut handles = HANDLES.write();
            let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle { context, kind } => kind.kwriteoff(id, context, buf),
        }
    }
    fn kfstat(&self, id: usize, buffer: UserSliceWo) -> Result<()> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buffer.copy_exactly(&Stat {
            st_mode: MODE_FILE | 0o666,
            st_size: handle.fsize()?,

            ..Stat::default()
        })?;

        Ok(())
    }

    fn fsize(&self, id: usize) -> Result<u64> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        handle.fsize()
    }

    /// Dup is currently used to implement clone() and execve().
    fn kdup(&self, old_id: usize, raw_buf: UserSliceRo, _: CallerCtx) -> Result<OpenResult> {
        let info = {
            let handles = HANDLES.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;

            handle.clone()
        };

        let handle = |h, positioned| {
            (
                h,
                if positioned {
                    InternalFlags::POSITIONED
                } else {
                    InternalFlags::empty()
                },
            )
        };
        let mut array = [0_u8; 64];
        if raw_buf.len() > array.len() {
            return Err(Error::new(EINVAL));
        }
        raw_buf.copy_to_slice(&mut array[..raw_buf.len()])?;
        let buf = &array[..raw_buf.len()];

        new_handle(match info {
            Handle {
                kind: ContextHandle::Authority,
                ..
            } => {
                return self
                    .open_inner(
                        OpenTy::Auth,
                        Some(core::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?)
                            .filter(|s| !s.is_empty()),
                        O_RDWR | O_CLOEXEC,
                    )
                    .map(|(r, fl)| OpenResult::SchemeLocal(r, fl))
            }
            Handle {
                kind: ContextHandle::OpenViaDup,
                context,
            } => {
                return self
                    .open_inner(
                        OpenTy::Ctxt(context),
                        Some(core::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?)
                            .filter(|s| !s.is_empty()),
                        O_RDWR | O_CLOEXEC,
                    )
                    .map(|(r, fl)| OpenResult::SchemeLocal(r, fl));
            }

            Handle {
                kind:
                    ContextHandle::Filetable {
                        ref filetable,
                        ref data,
                    },
                context,
            } => {
                // TODO: Maybe allow userspace to either copy or transfer recently dupped file
                // descriptors between file tables.
                if buf != b"copy" {
                    return Err(Error::new(EINVAL));
                }
                let filetable = filetable.upgrade().ok_or(Error::new(EOWNERDEAD))?;

                let new_filetable = Arc::try_new(RwLock::new(filetable.read().clone()))
                    .map_err(|_| Error::new(ENOMEM))?;

                handle(
                    Handle {
                        kind: ContextHandle::NewFiletable {
                            filetable: new_filetable,
                            data: data.clone(),
                        },
                        context,
                    },
                    true,
                )
            }
            Handle {
                kind: ContextHandle::AddrSpace { ref addrspace },
                context,
            } => {
                const GRANT_FD_PREFIX: &[u8] = b"grant-fd-";

                let kind = match buf {
                    // TODO: Better way to obtain new empty address spaces, perhaps using SYS_OPEN. But
                    // in that case, what scheme?
                    b"empty" => ContextHandle::AddrSpace {
                        addrspace: AddrSpaceWrapper::new()?,
                    },
                    b"exclusive" => ContextHandle::AddrSpace {
                        addrspace: addrspace.try_clone()?,
                    },
                    b"mmap-min-addr" => ContextHandle::MmapMinAddr(Arc::clone(addrspace)),

                    _ if buf.starts_with(GRANT_FD_PREFIX) => {
                        let string = core::str::from_utf8(&buf[GRANT_FD_PREFIX.len()..])
                            .map_err(|_| Error::new(EINVAL))?;
                        let page_addr =
                            usize::from_str_radix(string, 16).map_err(|_| Error::new(EINVAL))?;

                        if page_addr % PAGE_SIZE != 0 {
                            return Err(Error::new(EINVAL));
                        }

                        let page = Page::containing_address(VirtualAddress::new(page_addr));

                        match addrspace
                            .acquire_read()
                            .grants
                            .contains(page)
                            .ok_or(Error::new(EINVAL))?
                        {
                            (_, info) => {
                                return Ok(OpenResult::External(
                                    info.file_ref()
                                        .map(|r| Arc::clone(&r.description))
                                        .ok_or(Error::new(EBADF))?,
                                ))
                            }
                        }
                    }

                    _ => return Err(Error::new(EINVAL)),
                };

                handle(Handle { context, kind }, true)
            }
            _ => return Err(Error::new(EINVAL)),
        })
        .map(|(r, fl)| OpenResult::SchemeLocal(r, fl))
    }
}
fn extract_scheme_number(fd: usize) -> Result<(KernelSchemes, usize)> {
    let (scheme_id, number) = match &*context::current()
        .read()
        .get_file(FileHandle::from(fd))
        .ok_or(Error::new(EBADF))?
        .description
        .read()
    {
        desc => (desc.scheme, desc.number),
    };
    let scheme = scheme::schemes()
        .get(scheme_id)
        .ok_or(Error::new(ENODEV))?
        .clone();

    Ok((scheme, number))
}
fn verify_scheme(scheme: KernelSchemes) -> Result<()> {
    if !matches!(scheme, KernelSchemes::Global(GlobalSchemes::Proc)) {
        return Err(Error::new(EBADF));
    }
    Ok(())
}
impl Handle {
    fn fsize(&self) -> Result<u64> {
        match self.kind {
            ContextHandle::Filetable { ref data, .. }
            | ContextHandle::NewFiletable { ref data, .. } => Ok(data.len() as u64),
            _ => Ok(0),
        }
    }
}
impl ContextHandle {
    fn kwriteoff(
        self,
        id: usize,
        context: Arc<RwSpinlock<Context>>,
        buf: UserSliceRo,
    ) -> Result<usize> {
        match self {
            Self::AddrSpace { addrspace } => {
                let mut chunks = buf.usizes();
                let mut words_read = 0;
                let mut next = || {
                    words_read += 1;
                    chunks.next().ok_or(Error::new(EINVAL))
                };

                match next()?? {
                    op @ ADDRSPACE_OP_MMAP | op @ ADDRSPACE_OP_TRANSFER => {
                        let fd = next()??;
                        let offset = next()??;
                        let page_span = crate::syscall::validate_region(next()??, next()??)?;
                        let flags = MapFlags::from_bits(next()??).ok_or(Error::new(EINVAL))?;

                        if !flags.contains(MapFlags::MAP_FIXED) {
                            return Err(Error::new(EOPNOTSUPP));
                        }

                        let (scheme, number) = extract_scheme_number(fd)?;

                        scheme.kfmap(
                            number,
                            &addrspace,
                            &Map {
                                offset,
                                size: page_span.count * PAGE_SIZE,
                                address: page_span.base.start_address().data(),
                                flags,
                            },
                            op == ADDRSPACE_OP_TRANSFER,
                        )?;
                    }
                    ADDRSPACE_OP_MUNMAP => {
                        let page_span = crate::syscall::validate_region(next()??, next()??)?;

                        let unpin = false;
                        addrspace.munmap(page_span, unpin)?;
                    }
                    ADDRSPACE_OP_MPROTECT => {
                        let page_span = crate::syscall::validate_region(next()??, next()??)?;
                        let flags = MapFlags::from_bits(next()??).ok_or(Error::new(EINVAL))?;

                        addrspace.mprotect(page_span, flags)?;
                    }
                    _ => return Err(Error::new(EINVAL)),
                }
                Ok(words_read * mem::size_of::<usize>())
            }
            ContextHandle::Regs(kind) => match kind {
                RegsKind::Float => {
                    let regs = unsafe { buf.read_exact::<FloatRegisters>()? };

                    try_stop_context(context, |context| {
                        // NOTE: The kernel will never touch floats

                        // Ignore the rare case of floating point
                        // registers being uninitiated
                        let _ = context.set_fx_regs(regs);

                        Ok(mem::size_of::<FloatRegisters>())
                    })
                }
                RegsKind::Int => {
                    let regs = unsafe { buf.read_exact::<IntRegisters>()? };

                    try_stop_context(context, |context| match context.regs_mut() {
                        None => {
                            println!(
                                "{}:{}: Couldn't read registers from stopped process",
                                file!(),
                                line!()
                            );
                            Err(Error::new(ENOTRECOVERABLE))
                        }
                        Some(stack) => {
                            stack.load(&regs);

                            Ok(mem::size_of::<IntRegisters>())
                        }
                    })
                }
                RegsKind::Env => {
                    let regs = unsafe { buf.read_exact::<EnvRegisters>()? };
                    write_env_regs(context, regs)?;
                    Ok(mem::size_of::<EnvRegisters>())
                }
            },
            ContextHandle::Sighandler => {
                let data = unsafe { buf.read_exact::<SetSighandlerData>()? };

                if data.user_handler >= crate::USER_END_OFFSET
                    || data.excp_handler >= crate::USER_END_OFFSET
                {
                    return Err(Error::new(EPERM));
                }
                if data.thread_control_addr >= crate::USER_END_OFFSET
                    || data.proc_control_addr >= crate::USER_END_OFFSET
                {
                    return Err(Error::new(EFAULT));
                }

                let state = if data.thread_control_addr != 0 && data.proc_control_addr != 0 {
                    let validate_off = |addr, sz| {
                        let off = addr % PAGE_SIZE;
                        if off % mem::align_of::<usize>() == 0 && off + sz <= PAGE_SIZE {
                            Ok(off as u16)
                        } else {
                            Err(Error::new(EINVAL))
                        }
                    };

                    let addrsp = Arc::clone(context.read().addr_space()?);

                    Some(SignalState {
                        threadctl_off: validate_off(
                            data.thread_control_addr,
                            mem::size_of::<Sigcontrol>(),
                        )?,
                        procctl_off: validate_off(
                            data.proc_control_addr,
                            mem::size_of::<SigProcControl>(),
                        )?,
                        user_handler: NonZeroUsize::new(data.user_handler)
                            .ok_or(Error::new(EINVAL))?,
                        excp_handler: NonZeroUsize::new(data.excp_handler),
                        thread_control: addrsp.borrow_frame_enforce_rw_allocated(
                            Page::containing_address(VirtualAddress::new(data.thread_control_addr)),
                        )?,
                        proc_control: addrsp.borrow_frame_enforce_rw_allocated(
                            Page::containing_address(VirtualAddress::new(data.proc_control_addr)),
                        )?,
                    })
                } else {
                    None
                };

                context.write().sig = state;

                Ok(mem::size_of::<SetSighandlerData>())
            }
            ContextHandle::Start => match context.write().status {
                ref mut status @ Status::HardBlocked {
                    reason: HardBlockedReason::NotYetStarted,
                } => {
                    *status = Status::Runnable;
                    Ok(buf.len())
                }
                _ => return Err(Error::new(EINVAL)),
            },
            ContextHandle::Filetable { .. } | ContextHandle::NewFiletable { .. } => {
                Err(Error::new(EBADF))
            }

            ContextHandle::CurrentFiletable => {
                let filetable_fd = buf.read_usize()?;
                let (hopefully_this_scheme, number) = extract_scheme_number(filetable_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Entry::Occupied(mut entry) = handles.entry(number) else {
                    return Err(Error::new(EBADF));
                };
                let filetable = match *entry.get_mut() {
                    Handle {
                        kind: ContextHandle::Filetable { ref filetable, .. },
                        ..
                    } => filetable.upgrade().ok_or(Error::new(EOWNERDEAD))?,
                    Handle {
                        kind:
                            ContextHandle::NewFiletable {
                                ref filetable,
                                ref data,
                            },
                        ..
                    } => {
                        let ft = Arc::clone(&filetable);
                        *entry.get_mut() = Handle {
                            kind: ContextHandle::Filetable {
                                filetable: Arc::downgrade(&filetable),
                                data: data.clone(),
                            },
                            context: Arc::clone(&context),
                        };
                        ft
                    }

                    _ => return Err(Error::new(EBADF)),
                };

                *handles.get_mut(&id).ok_or(Error::new(EBADF))? = Handle {
                    kind: ContextHandle::AwaitingFiletableChange { new_ft: filetable },
                    context,
                };

                Ok(mem::size_of::<usize>())
            }
            ContextHandle::CurrentAddrSpace { .. } => {
                let mut iter = buf.usizes();
                let addrspace_fd = iter.next().ok_or(Error::new(EINVAL))??;
                let sp = iter.next().ok_or(Error::new(EINVAL))??;
                let ip = iter.next().ok_or(Error::new(EINVAL))??;

                let (hopefully_this_scheme, number) = extract_scheme_number(addrspace_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Handle {
                    kind: ContextHandle::AddrSpace { ref addrspace },
                    ..
                } = handles.get(&number).ok_or(Error::new(EBADF))?
                else {
                    return Err(Error::new(EBADF));
                };

                *handles.get_mut(&id).ok_or(Error::new(EBADF))? = Handle {
                    context,
                    kind: Self::AwaitingAddrSpaceChange {
                        new: Arc::clone(addrspace),
                        new_sp: sp,
                        new_ip: ip,
                    },
                };

                Ok(3 * mem::size_of::<usize>())
            }
            Self::MmapMinAddr(ref addrspace) => {
                let val = buf.read_usize()?;
                if val % PAGE_SIZE != 0 || val > crate::USER_END_OFFSET {
                    return Err(Error::new(EINVAL));
                }
                addrspace.acquire_write().mmap_min = val;
                Ok(mem::size_of::<usize>())
            }
            Self::SchedAffinity => {
                let mask = unsafe { buf.read_exact::<crate::cpu_set::RawMask>()? };

                context.write().sched_affinity.override_from(&mask);

                Ok(mem::size_of_val(&mask))
            }
            ContextHandle::Status { privileged } => {
                let mut args = buf.usizes();

                let user_data = args.next().ok_or(Error::new(EINVAL))??;

                let context_verb =
                    ContextVerb::try_from_raw(user_data).ok_or(Error::new(EINVAL))?;

                match context_verb {
                    // TODO: lwp_park/lwp_unpark for bypassing procmgr?
                    ContextVerb::Unstop | ContextVerb::Stop if !privileged => {
                        return Err(Error::new(EPERM))
                    }
                    ContextVerb::Stop => {
                        let mut guard = context.write();

                        match guard.status {
                            Status::Dead { .. } => return Err(Error::new(EOWNERDEAD)),
                            Status::HardBlocked {
                                reason: HardBlockedReason::AwaitingMmap { .. },
                            } => todo!(),
                            _ => (),
                        }
                        guard.status = Status::HardBlocked {
                            reason: HardBlockedReason::Stopped,
                        };
                        // TODO: wait for context to be switched away from, and/or IPI?
                        Ok(size_of::<usize>())
                    }
                    ContextVerb::Unstop => {
                        let mut guard = context.write();

                        if let Status::HardBlocked {
                            reason: HardBlockedReason::Stopped,
                        } = guard.status
                        {
                            guard.status = Status::Runnable;
                        }
                        Ok(size_of::<usize>())
                    }
                    ContextVerb::Interrupt => {
                        let mut guard = context.write();
                        guard.unblock();
                        Ok(size_of::<usize>())
                    }
                    ContextVerb::ForceKill => {
                        if context::is_current(&context) {
                            //log::trace!("FORCEKILL SELF {} {}", context.read().debug_id, context.read().pid);

                            // The following functionality simplifies the cleanup step when detached threads
                            // terminate.
                            if let Some(post_unmap) = args.next() {
                                let base = post_unmap?;
                                let size = args.next().ok_or(Error::new(EINVAL))??;

                                if size > 0 {
                                    let addrsp = Arc::clone(context.read().addr_space()?);
                                    let res = addrsp.munmap(
                                        PageSpan::validate_nonempty(
                                            VirtualAddress::new(base),
                                            size,
                                        )
                                        .ok_or(Error::new(EINVAL))?,
                                        false,
                                    )?;
                                    for r in res {
                                        let _ = r.unmap();
                                    }
                                }
                            }
                            crate::syscall::exit_this_context(None);
                        } else {
                            let mut ctxt = context.write();
                            //log::trace!("FORCEKILL NONSELF={} {}, SELF={}", ctxt.debug_id, ctxt.pid, context::current().read().debug_id);
                            ctxt.status = context::Status::Runnable;
                            ctxt.being_sigkilled = true;
                            Ok(mem::size_of::<usize>())
                        }
                    }
                }
            }
            ContextHandle::Attr => {
                let info = unsafe { buf.read_exact::<ProcSchemeAttrs>()? };
                let mut guard = context.write();

                let len = info
                    .debug_name
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(info.debug_name.len())
                    .min(guard.name.capacity());
                let debug_name = core::str::from_utf8(&info.debug_name[..len])
                    .map_err(|_| Error::new(EINVAL))?;
                guard.name.clear();
                guard.name.push_str(debug_name);

                guard.pid = info.pid as usize;
                guard.ens = (info.ens as usize).into();
                guard.euid = info.euid;
                guard.egid = info.egid;
                Ok(size_of::<ProcSchemeAttrs>())
            }
            _ => Err(Error::new(EBADF)),
        }
    }
    fn kreadoff(
        &self,
        _id: usize,
        context: Arc<RwSpinlock<Context>>,
        buf: UserSliceWo,
        offset: u64,
    ) -> Result<usize> {
        match self {
            ContextHandle::Regs(kind) => {
                union Output {
                    float: FloatRegisters,
                    int: IntRegisters,
                    env: EnvRegisters,
                }

                let (output, size) = match kind {
                    RegsKind::Float => {
                        let context = context.read();
                        // NOTE: The kernel will never touch floats

                        (
                            Output {
                                float: context.get_fx_regs(),
                            },
                            mem::size_of::<FloatRegisters>(),
                        )
                    }
                    RegsKind::Int => try_stop_context(context, |context| match context.regs() {
                        None => {
                            assert!(!context.running, "try_stop_context is broken, clearly");
                            println!(
                                "{}:{}: Couldn't read registers from stopped process",
                                file!(),
                                line!()
                            );
                            Err(Error::new(ENOTRECOVERABLE))
                        }
                        Some(stack) => {
                            let mut regs = IntRegisters::default();
                            stack.save(&mut regs);
                            Ok((Output { int: regs }, mem::size_of::<IntRegisters>()))
                        }
                    })?,
                    RegsKind::Env => (
                        Output {
                            env: read_env_regs(context)?,
                        },
                        mem::size_of::<EnvRegisters>(),
                    ),
                };

                let src_buf =
                    unsafe { slice::from_raw_parts(&output as *const _ as *const u8, size) };

                buf.copy_common_bytes_from_slice(src_buf)
            }
            ContextHandle::AddrSpace { ref addrspace } => {
                let Ok(offset) = usize::try_from(offset) else {
                    return Ok(0);
                };
                let grants_to_skip = offset / mem::size_of::<GrantDesc>();

                // Output a list of grant descriptors, sufficient to allow relibc's fork()
                // implementation to fmap MAP_SHARED grants.
                let mut grants_read = 0;

                let mut dst = [GrantDesc::default(); 16];

                for (dst, (grant_base, grant_info)) in dst
                    .iter_mut()
                    .zip(addrspace.acquire_read().grants.iter().skip(grants_to_skip))
                {
                    *dst = GrantDesc {
                        base: grant_base.start_address().data(),
                        size: grant_info.page_count() * PAGE_SIZE,
                        flags: grant_info.grant_flags(),
                        // The !0 is not a sentinel value; the availability of `offset` is
                        // indicated by the GRANT_SCHEME flag.
                        offset: grant_info.file_ref().map_or(!0, |f| f.base_offset as u64),
                    };
                    grants_read += 1;
                }
                for (src, chunk) in dst
                    .iter()
                    .take(grants_read)
                    .zip(buf.in_exact_chunks(mem::size_of::<GrantDesc>()))
                {
                    chunk.copy_exactly(src)?;
                }

                Ok(grants_read * mem::size_of::<GrantDesc>())
            }

            ContextHandle::Filetable { data, .. } => read_from(buf, &data, offset),
            ContextHandle::MmapMinAddr(ref addrspace) => {
                buf.write_usize(addrspace.acquire_read().mmap_min)?;
                Ok(mem::size_of::<usize>())
            }
            ContextHandle::SchedAffinity => {
                let mask = context.read().sched_affinity.to_raw();

                buf.copy_exactly(crate::cpu_set::mask_as_bytes(&mask))?;
                Ok(mem::size_of_val(&mask))
            } // TODO: Replace write() with SYS_SENDFD?
            ContextHandle::Status { .. } => {
                let status = {
                    let context = context.read();
                    match context.status {
                        Status::Dead { excp: None } => ContextStatus::Dead,
                        Status::Runnable if context.being_sigkilled => ContextStatus::ForceKilled,
                        Status::Dead { excp: Some(excp) } => {
                            let (status, payload) =
                                buf.split_at(size_of::<usize>()).ok_or(Error::new(EINVAL))?;
                            status.copy_from_slice(
                                &(ContextStatus::UnhandledExcp as usize).to_ne_bytes(),
                            )?;
                            let len = payload.copy_common_bytes_from_slice(&excp)?;
                            return Ok(size_of::<usize>() + len);
                        }
                        Status::Runnable => ContextStatus::Runnable,
                        Status::Blocked => ContextStatus::Blocked,
                        Status::HardBlocked {
                            reason: HardBlockedReason::NotYetStarted,
                        } => ContextStatus::NotYetStarted,
                        Status::HardBlocked {
                            reason: HardBlockedReason::Stopped,
                        } => ContextStatus::Stopped,
                        _ => ContextStatus::Other,
                    }
                };
                buf.copy_common_bytes_from_slice(&(status as usize).to_ne_bytes())
            }
            ContextHandle::Attr => {
                let mut debug_name = [0; 32];
                let (euid, egid, ens, pid, name) = match context.read() {
                    ref c => (c.euid, c.egid, c.ens.get() as u32, c.pid as u32, c.name),
                };
                let min = name.len().min(debug_name.len());
                debug_name[..min].copy_from_slice(&name.as_bytes()[..min]);
                buf.copy_common_bytes_from_slice(&ProcSchemeAttrs {
                    pid,
                    euid,
                    egid,
                    ens,
                    debug_name,
                })
            }
            ContextHandle::Sighandler => {
                let data = match context.read().sig {
                    Some(ref sig) => SetSighandlerData {
                        excp_handler: sig.excp_handler.map_or(0, NonZeroUsize::get),
                        user_handler: sig.user_handler.get(),
                        proc_control_addr: sig.procctl_off.into(),
                        thread_control_addr: sig.threadctl_off.into(),
                    },
                    None => SetSighandlerData::default(),
                };
                buf.copy_common_bytes_from_slice(&data)
            }

            // TODO: Find a better way to switch address spaces, since they also require switching
            // the instruction and stack pointer. Maybe remove `<pid>/regs` altogether and replace it
            // with `<pid>/ctx`
            _ => return Err(Error::new(EBADF)),
        }
    }
}

fn write_env_regs(context: Arc<RwSpinlock<Context>>, regs: EnvRegisters) -> Result<()> {
    if context::is_current(&context) {
        context::current().write().write_current_env_regs(regs)
    } else {
        try_stop_context(context, |context| context.write_env_regs(regs))
    }
}

fn read_env_regs(context: Arc<RwSpinlock<Context>>) -> Result<EnvRegisters> {
    if context::is_current(&context) {
        context::current().read().read_current_env_regs()
    } else {
        try_stop_context(context, |context| context.read_env_regs())
    }
}
