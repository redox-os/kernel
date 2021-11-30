//! # Futex
//! Futex or Fast Userspace Mutex is "a method for waiting until a certain condition becomes true."
//!
//! For more information about futexes, please read [this](https://eli.thegreenplace.net/2018/basics-of-futexes/) blog post, and the [futex(2)](http://man7.org/linux/man-pages/man2/futex.2.html) man page
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use core::intrinsics;
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use rmm::Arch;

use crate::context::{self, Context};
use crate::time;
use crate::memory::PhysicalAddress;
use crate::paging::{ActivePageTable, TableKind, VirtualAddress};
use crate::syscall::data::TimeSpec;
use crate::syscall::error::{Error, Result, ESRCH, EAGAIN, EFAULT, EINVAL};
use crate::syscall::flag::{FUTEX_WAIT, FUTEX_WAIT64, FUTEX_WAKE, FUTEX_REQUEUE};
use crate::syscall::validate::validate_array;

type FutexList = VecDeque<FutexEntry>;

pub struct FutexEntry {
    target_physaddr: PhysicalAddress,
    context_lock: Arc<RwLock<Context>>,
}

/// Fast userspace mutex list
static FUTEXES: Once<RwLock<FutexList>> = Once::new();

/// Initialize futexes, called if needed
fn init_futexes() -> RwLock<FutexList> {
    RwLock::new(VecDeque::new())
}

/// Get the global futexes list, const
pub fn futexes() -> RwLockReadGuard<'static, FutexList> {
    FUTEXES.call_once(init_futexes).read()
}

/// Get the global futexes list, mutable
pub fn futexes_mut() -> RwLockWriteGuard<'static, FutexList> {
    FUTEXES.call_once(init_futexes).write()
}

pub fn futex(addr: usize, op: usize, val: usize, val2: usize, addr2: usize) -> Result<usize> {
    let target_physaddr = unsafe {
        let active_table = ActivePageTable::new(TableKind::User);
        let virtual_address = VirtualAddress::new(addr);

        if !crate::CurrentRmmArch::virt_is_valid(virtual_address) {
            return Err(Error::new(EFAULT));
        }
        // TODO: Use this all over the code, making sure that no user pointers that are higher half
        // can get to the page table walking procedure.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if virtual_address.data() & (1 << 63) == (1 << 63) {
            return Err(Error::new(EFAULT));
        }

        active_table.translate(virtual_address).ok_or(Error::new(EFAULT))?
    };

    match op {
        // TODO: FUTEX_WAIT_MULTIPLE?
        FUTEX_WAIT | FUTEX_WAIT64 => {
            let timeout_ptr = val2 as *const TimeSpec;

            let timeout_opt = if timeout_ptr.is_null() {
                None
            } else {
                let [timeout] = unsafe { *validate_array(timeout_ptr)? };
                Some(timeout)
            };

            {
                let mut futexes = futexes_mut();

                let context_lock = {
                    let contexts = context::contexts();
                    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                    Arc::clone(&context_lock)
                };

                // TODO: Is the implicit SeqCst ordering too strong here?
                let (fetched, expected) = if op == FUTEX_WAIT {
                    // Must be aligned, otherwise it could cross a page boundary and mess up the
                    // (simpler) validation we did in the first place.
                    if addr % 4 != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    (u64::from(unsafe { intrinsics::atomic_load::<u32>(addr as *const u32) }), u64::from(val as u32))
                } else {
                    // op == FUTEX_WAIT64
                    if addr % 8 != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    (unsafe { intrinsics::atomic_load::<u64>(addr as *const u64) }, val as u64)
                };
                if fetched != expected {
                    return Err(Error::new(EAGAIN));
                }

                {
                    let mut context = context_lock.write();

                    if let Some(timeout) = timeout_opt {
                        let start = time::monotonic();
                        let sum = start.1 + timeout.tv_nsec as u64;
                        let end = (start.0 + timeout.tv_sec as u64 + sum / 1_000_000_000, sum % 1_000_000_000);
                        context.wake = Some(end);
                    }

                    context.block("futex");
                }

                futexes.push_back(FutexEntry {
                    target_physaddr,
                    context_lock,
                });
            }

            unsafe { context::switch(); }

            if timeout_opt.is_some() {
                let context_lock = {
                    let contexts = context::contexts();
                    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                    Arc::clone(&context_lock)
                };

                {
                    let mut context = context_lock.write();
                    context.wake = None;
                }
            }

            Ok(0)
        },
        FUTEX_WAKE => {
            let mut woken = 0;

            {
                let mut futexes = futexes_mut();

                let mut i = 0;

                // TODO: Use retain, once it allows the closure to tell it to stop iterating...
                while i < futexes.len() && woken < val {
                    if futexes[i].target_physaddr != target_physaddr {
                        i += 1;
                        continue;
                    }
                    if let Some(futex) = futexes.swap_remove_back(i) {
                        let mut context_guard = futex.context_lock.write();
                        context_guard.unblock();
                        woken += 1;
                    }
                }
            }

            Ok(woken)
        },
        FUTEX_REQUEUE => {
            let addr2_physaddr = unsafe {
                let addr2_virt = VirtualAddress::new(addr2);

                if !crate::CurrentRmmArch::virt_is_valid(addr2_virt) {
                    return Err(Error::new(EFAULT));
                }

                // TODO
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                if addr2_virt.data() & (1 << 63) == (1 << 63) {
                    return Err(Error::new(EFAULT));
                }

                let active_table = ActivePageTable::new(TableKind::User);
                active_table.translate(addr2_virt).ok_or(Error::new(EFAULT))?
            };

            let mut woken = 0;
            let mut requeued = 0;

            {
                let mut futexes = futexes_mut();

                let mut i = 0;
                while i < futexes.len() && woken < val {
                    if futexes[i].target_physaddr != target_physaddr {
                        i += 1;
                    }
                    if let Some(futex) = futexes.swap_remove_back(i) {
                        futex.context_lock.write().unblock();
                        woken += 1;
                    }
                }
                while i < futexes.len() && requeued < val2 {
                    if futexes[i].target_physaddr != target_physaddr {
                        i += 1;
                    }
                    futexes[i].target_physaddr = addr2_physaddr;
                    requeued += 1;
                }
            }

            Ok(woken)
        },
        _ => Err(Error::new(EINVAL))
    }
}
