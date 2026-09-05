use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::ordered::{Mutex, L4};
use spin::Once;

use syscall::data::GlobalSchemes;

use crate::{
    acpi::{RxsdtEnum, RXSDT_ENUM},
    context::file::InternalFlags,
    scheme::{SchemeExt, StrOrBytes},
    sync::CleanLockToken,
};

use crate::syscall::{
    error::{Error, Result, EACCES, EBADFD, EINVAL, EIO, ENOENT},
    flag::{AcpiVerb, CallFlags, EventFlags},
    usercopy::UserSliceRw,
};

use super::{CallerCtx, KernelScheme, OpenResult};

/// A scheme used to access the RSDT or XSDT, and listen for shutdown, which is needed for e.g. `acpid` to function.
pub struct AcpiScheme;

bitflags! {
    #[derive(PartialEq)]
    struct HandleBits: usize {
        const CAN_READ_RXSDT = 1;
        const CAN_REGISTER_KSTOP = 2;

        // mutually exclusive with the other flags
        const KSTOP_HANDLE = 4;

        // TODO: More fine-grained access control should be added, such as capabilities for certain
        // MSR ranges, and for read/write (there are 2^32 MSRs on x86).
        // TODO: The ACPI scheme is not the best place for this, but makes most sense for now as
        // MSRs are only used for x86_64 profiling, where acpi is necessary to be able to start APs
        // in the first place.
        const MSR_HANDLE = 8;
    }
}

static RXSDT_DATA: Once<Box<[u8]>> = Once::new();

static KSTOP_FLAG: Mutex<L4, bool> = Mutex::new(false);
static EXISTS_KSTOP_HANDLE: AtomicBool = AtomicBool::new(false);

pub fn register_kstop(token: &mut CleanLockToken) -> bool {
    *KSTOP_FLAG.lock(token.token()) = true;

    if !EXISTS_KSTOP_HANDLE.load(Ordering::Relaxed) {
        error!("No userspace ACPI handler was notified when trying to shutdown. This is bad.");
        // Let the kernel shutdown without ACPI.
        return false;
    }
    crate::event::trigger(
        GlobalSchemes::Acpi.scheme_id(),
        HandleBits::KSTOP_HANDLE.bits(),
        EventFlags::EVENT_READ,
        token,
    );

    // TODO: Context switch directly to the waiting context, to avoid annoying timeouts.
    true
}

impl AcpiScheme {
    pub fn init() {
        // NOTE: This __must__ be called from the main kernel context, while initializing all
        // schemes. If it is called by any other context, then all ACPI data will probably not even
        // be mapped.

        let mut data_init = false;

        RXSDT_DATA.call_once(|| {
            data_init = true;

            let table = match RXSDT_ENUM.get() {
                Some(RxsdtEnum::Rsdt(rsdt)) => rsdt.as_slice(),
                Some(RxsdtEnum::Xsdt(xsdt)) => xsdt.as_slice(),
                None => {
                    warn!("expected RXSDT_ENUM to be initialized before AcpiScheme, is ACPI available?");
                    &[]
                }
            };

            Box::from(table)
        });

        if !data_init {
            error!("AcpiScheme::init called multiple times");
        }
    }
}

impl KernelScheme for AcpiScheme {
    fn scheme_root(&self, _token: &mut CleanLockToken) -> Result<usize> {
        Ok((HandleBits::CAN_READ_RXSDT | HandleBits::CAN_REGISTER_KSTOP).bits())
    }
    fn kopenat(
        &self,
        id: usize,
        path: StrOrBytes,
        _flags: usize,
        _fcntl_flags: u32,
        caller: CallerCtx,
        _token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let bits = HandleBits::from_bits_retain(id);

        let new_bits = match path.as_bytes() {
            b"" | b"/" => bits,
            b"kstop" | b"/kstop" => {
                // TODO: can the uid check be removed?
                if caller.uid != 0 || !bits.contains(HandleBits::CAN_REGISTER_KSTOP) {
                    return Err(Error::new(EACCES));
                }
                EXISTS_KSTOP_HANDLE.store(true, Ordering::Relaxed);
                HandleBits::KSTOP_HANDLE
            }
            b"msr" if cfg!(target_arch = "x86_64") => {
                if caller.uid != 0 {
                    return Err(Error::new(EACCES));
                }
                HandleBits::MSR_HANDLE
            }
            _ => return Err(Error::new(ENOENT)),
        };
        Ok(OpenResult::SchemeLocal(
            new_bits.bits(),
            InternalFlags::empty(),
        ))
    }
    fn kcall(
        &self,
        fds: &[usize],
        payload: UserSliceRw,
        flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let [handle] = <&[usize; 1]>::try_from(fds)
            .map_err(|_| Error::new(EINVAL))?
            .map(HandleBits::from_bits_retain);
        let verb = metadata
            .first()
            .copied()
            .and_then(AcpiVerb::try_from_raw)
            .ok_or(Error::new(EINVAL))?;

        match verb {
            AcpiVerb::ReadRxsdt => {
                if !handle.contains(HandleBits::CAN_READ_RXSDT) || !flags.contains(CallFlags::READ)
                {
                    return Err(Error::new(EINVAL));
                }
                let src = RXSDT_DATA.get().ok_or(Error::new(EBADFD))?;
                payload.copy_common_bytes_from_slice(src)?;
                Ok(src.len())
            }
            AcpiVerb::CheckShutdown => {
                if handle != HandleBits::KSTOP_HANDLE {
                    return Err(Error::new(EINVAL));
                }
                Ok(usize::from(*KSTOP_FLAG.lock(token.token())))
            }
            AcpiVerb::Msr => {
                if handle != HandleBits::MSR_HANDLE {
                    return Err(Error::new(EINVAL));
                }
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::arch::misc::MsrFault;

                    let register = *metadata.get(1).ok_or(Error::new(EINVAL))? as u32;

                    let write_data = if flags.contains(CallFlags::WRITE) {
                        Some(payload.read_usize()? as u64)
                    } else {
                        None
                    };
                    if flags.contains(CallFlags::READ) {
                        let value = crate::arch::misc::rdmsr_safe(register)
                            .map_err(|MsrFault| Error::new(EIO))?;

                        debug!("MSR READ {register:x} => {value:x}");
                        payload.write_usize(value as usize)?;
                    }
                    if let Some(write_data) = write_data {
                        debug!("MSR WRITE {register:x} <= {write_data:x}");

                        crate::arch::misc::wrmsr_safe(register, write_data)
                            .map_err(|MsrFault| Error::new(EIO))?;
                    }

                    Ok(0)
                }

                #[cfg(not(target_arch = "x86_64"))]
                return Err(Error::new(EOPNOTSUPP));
            }
        }
    }
}
