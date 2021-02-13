//! # Futex
//! Futex or Fast Userspace Mutex is "a method for waiting until a certain condition becomes true."
//!
//! For more information about futexes, please read [this](https://eli.thegreenplace.net/2018/basics-of-futexes/) blog post, and the [futex(2)](http://man7.org/linux/man-pages/man2/futex.2.html) man page
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use core::intrinsics;
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::context::{self, Context};
use crate::time;
use crate::memory::PhysicalAddress;
use crate::paging::{ActivePageTable, VirtualAddress};
use crate::syscall::data::TimeSpec;
use crate::syscall::error::{Error, Result, ESRCH, EAGAIN, EFAULT, EINVAL};
use crate::syscall::flag::{FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE};
use crate::syscall::validate::{validate_slice, validate_slice_mut};

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

// FIXME: Don't take a mutable reference to the addr, since rustc can make assumptions that the
// pointee cannot be changed by another thread, which could make atomic ops useless.
pub fn futex(addr: &mut i32, op: usize, val: i32, val2: usize, addr2: *mut i32) -> Result<usize> {
    let target_physaddr = unsafe {
        let mut active_table = ActivePageTable::new();
        let virtual_address = VirtualAddress::new(addr as *mut i32 as usize);

        // FIXME: Already validated in syscall/mod.rs
        active_table.translate(virtual_address).ok_or(Error::new(EFAULT))?
    };

    match op {
        FUTEX_WAIT => {
            let timeout_opt = if val2 != 0 {
                Some(validate_slice(val2 as *const TimeSpec, 1).map(|req| &req[0])?)
            } else {
                None
            };

            {
                let mut futexes = futexes_mut();

                let context_lock = {
                    let contexts = context::contexts();
                    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                    Arc::clone(&context_lock)
                };

                if unsafe { intrinsics::atomic_load(addr) != val } {
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
                while i < futexes.len() && (woken as i32) < val {
                    if futexes[i].target_physaddr == target_physaddr {
                        if let Some(futex) = futexes.swap_remove_back(i) {
                            let mut context_guard = futex.context_lock.write();
                            context_guard.unblock();
                            woken += 1;
                        }
                    } else {
                        i += 1;
                    }
                }
            }

            Ok(woken)
        },
        FUTEX_REQUEUE => {
            let addr2_physaddr = unsafe {
                let mut active_table = ActivePageTable::new();

                let addr2_safe = validate_slice_mut(addr2, 1).map(|addr2_safe| &mut addr2_safe[0])?;
                let addr2_virt = VirtualAddress::new(addr2_safe as *mut i32 as usize);

                // FIXME: Already validated.
                active_table.translate(addr2_virt).ok_or(Error::new(EFAULT))?
            };

            let mut woken = 0;
            let mut requeued = 0;

            {
                let mut futexes = futexes_mut();

                let mut i = 0;
                while i < futexes.len() && (woken as i32) < val {
                    if futexes[i].target_physaddr == target_physaddr {
                        if let Some(futex) = futexes.swap_remove_back(i) {
                            futex.context_lock.write().unblock();
                            woken += 1;
                        }
                    } else {
                        i += 1;
                    }
                }
                while i < futexes.len() && requeued < val2 {
                    if futexes[i].target_physaddr == target_physaddr {
                        futexes[i].target_physaddr = addr2_physaddr;
                        requeued += 1;
                    }
                    i += 1;
                }
            }

            Ok(woken)
        },
        _ => Err(Error::new(EINVAL))
    }
}
