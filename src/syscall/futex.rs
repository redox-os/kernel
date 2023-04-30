//! # Futex
//! Futex or Fast Userspace Mutex is "a method for waiting until a certain condition becomes true."
//!
//! For more information about futexes, please read [this](https://eli.thegreenplace.net/2018/basics-of-futexes/) blog post, and the [futex(2)](http://man7.org/linux/man-pages/man2/futex.2.html) man page
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::intrinsics;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use rmm::Arch;

use crate::context::{self, memory::AddrSpace, Context};
use crate::memory::PhysicalAddress;
use crate::paging::{Page, VirtualAddress};
use crate::time;

use crate::syscall::data::TimeSpec;
use crate::syscall::error::{Error, Result, EAGAIN, EFAULT, EINVAL, ESRCH};
use crate::syscall::flag::{FUTEX_REQUEUE, FUTEX_WAIT, FUTEX_WAIT64, FUTEX_WAKE};
use crate::syscall::validate::validate_array;

type FutexList = VecDeque<FutexEntry>;

pub struct FutexEntry {
    target_physaddr: PhysicalAddress,
    context_lock: Arc<RwLock<Context>>,
}

// TODO: Process-private futexes? In that case, put the futex table in each AddrSpace.
// TODO: Hash table?
static FUTEXES: RwLock<FutexList> = RwLock::new(FutexList::new());

fn validate_and_translate_virt(space: &AddrSpace, addr: VirtualAddress) -> Option<PhysicalAddress> {
    // TODO: Move this elsewhere!
    if addr.data().saturating_add(core::mem::size_of::<usize>()) >= crate::USER_END_OFFSET {
        return None;
    }

    let page = Page::containing_address(addr);
    let off = addr.data() - page.start_address().data();

    let (frame, _) = space.table.utable.translate(page.start_address())?;

    Some(frame.add(off))
}

pub fn futex(addr: usize, op: usize, val: usize, val2: usize, addr2: usize) -> Result<usize> {
    let addr_space = Arc::clone(context::current()?.read().addr_space()?);

    let target_physaddr =
        validate_and_translate_virt(&*addr_space.read(), VirtualAddress::new(addr))
            .ok_or(Error::new(EFAULT))?;

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
                let mut futexes = FUTEXES.write();

                let context_lock = context::current()?;

                let (fetched, expected) = if op == FUTEX_WAIT {
                    // Must be aligned, otherwise it could cross a page boundary and mess up the
                    // (simpler) validation we did in the first place.
                    if addr % 4 != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    (
                        u64::from(unsafe {
                            intrinsics::atomic_load_seqcst::<u32>(addr as *const u32)
                        }),
                        u64::from(val as u32),
                    )
                } else {
                    // op == FUTEX_WAIT64
                    if addr % 8 != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    (
                        unsafe { intrinsics::atomic_load_seqcst::<u64>(addr as *const u64) },
                        val as u64,
                    )
                };
                if fetched != expected {
                    return Err(Error::new(EAGAIN));
                }

                {
                    let mut context = context_lock.write();

                    if let Some(timeout) = timeout_opt {
                        let start = time::monotonic();
                        let end = start
                            + (timeout.tv_sec as u128 * time::NANOS_PER_SEC)
                            + (timeout.tv_nsec as u128);
                        context.wake = Some(end);
                    }

                    context.block("futex");
                }

                futexes.push_back(FutexEntry {
                    target_physaddr,
                    context_lock,
                });
            }

            unsafe {
                context::switch();
            }

            if timeout_opt.is_some() {
                let context_lock = {
                    let contexts = context::contexts();
                    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                    Arc::clone(context_lock)
                };

                {
                    let mut context = context_lock.write();
                    context.wake = None;
                }
            }

            Ok(0)
        }
        FUTEX_WAKE => {
            let mut woken = 0;

            {
                let mut futexes = FUTEXES.write();

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
        }
        FUTEX_REQUEUE => {
            let addr2_physaddr =
                validate_and_translate_virt(&*addr_space.read(), VirtualAddress::new(addr2))
                    .ok_or(Error::new(EFAULT))?;

            let mut woken = 0;
            let mut requeued = 0;

            {
                let mut futexes = FUTEXES.write();

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
        }
        _ => Err(Error::new(EINVAL)),
    }
}
