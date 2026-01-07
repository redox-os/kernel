//! # Futex
//! Futex or Fast Userspace Mutex is "a method for waiting until a certain condition becomes true."
//!
//! For more information about futexes, please read [this](https://eli.thegreenplace.net/2018/basics-of-futexes/) blog post, and the [futex(2)](http://man7.org/linux/man-pages/man2/futex.2.html) man page
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, Ordering};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use rmm::Arch;
use syscall::EINTR;

use crate::{
    context::{
        self,
        memory::{AddrSpace, AddrSpaceWrapper},
        ContextLock,
    },
    memory::PhysicalAddress,
    paging::{Page, VirtualAddress},
    sync::{CleanLockToken, Mutex, L1},
    time,
};

use crate::syscall::{
    data::TimeSpec,
    error::{Error, Result, EAGAIN, EFAULT, EINVAL, ETIMEDOUT},
    flag::{FUTEX_WAIT, FUTEX_WAIT64, FUTEX_WAKE},
};

use super::usercopy::UserSlice;

// Physical address used as key, required if synchronizing across address spaces
// (necessitates MAP_SHARED since CoW would invalidate this address).
type FutexList = HashMap<PhysicalAddress, Vec<FutexEntry>>;

pub struct FutexEntry {
    // Virtual address, required if synchronizing across the same address space, if the memory is
    // CoW.
    // TODO: FUTEX_REQUEUE
    target_virtaddr: VirtualAddress,
    // Context to wake up, and compare address spaces.
    context_lock: Arc<ContextLock>,
    // address space to check against if virt matches but not phys
    addr_space: Weak<AddrSpaceWrapper>,
}

// TODO: Process-private futexes? In that case, put the futex table in each AddrSpace, or just
// implement that fully in userspace. Although futex is probably the best API for process-shared
// POSIX synchronization primitives, a local hash table and wait-for-thread kernel APIs (e.g.
// lwp_park/lwp_unpark from NetBSD) could be a simpler replacement.
static FUTEXES: Mutex<L1, FutexList> =
    Mutex::new(FutexList::with_hasher(DefaultHashBuilder::new()));

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

pub fn futex(
    addr: usize,
    op: usize,
    val: usize,
    val2: usize,
    _addr2: usize,
    token: &mut CleanLockToken,
) -> Result<usize> {
    let current_addrsp = AddrSpace::current()?;

    // Keep the address space locked so we can safely read from the physical address. Unlock it
    // before context switching.
    let addr_space_guard = current_addrsp.acquire_read();

    let target_virtaddr = VirtualAddress::new(addr);
    let target_physaddr = validate_and_translate_virt(&addr_space_guard, target_virtaddr)
        .ok_or(Error::new(EFAULT))?;

    match op {
        // TODO: FUTEX_WAIT_MULTIPLE?
        FUTEX_WAIT | FUTEX_WAIT64 => {
            let timeout_opt = UserSlice::ro(val2, core::mem::size_of::<TimeSpec>())?
                .none_if_null()
                .map(|buf| unsafe { buf.read_exact::<TimeSpec>() })
                .transpose()?;

            let context_lock = context::current();

            {
                let mut futexes = FUTEXES.lock(token.token());
                let (futexes, mut token) = futexes.token_split();

                let (fetched, expected) = if op == FUTEX_WAIT {
                    // Must be aligned, otherwise it could cross a page boundary and mess up the
                    // (simpler) validation we did in the first place.
                    if addr % 4 != 0 {
                        return Err(Error::new(EINVAL));
                    }

                    // On systems where virtual memory is not abundant, we might instead add an
                    // atomic usercopy function.
                    let accessible_addr =
                        unsafe { crate::paging::RmmA::phys_to_virt(target_physaddr) }.data();

                    (
                        u64::from(unsafe {
                            (*(accessible_addr as *const AtomicU32)).load(Ordering::SeqCst)
                        }),
                        u64::from(val as u32),
                    )
                } else {
                    #[cfg(target_has_atomic = "64")]
                    {
                        use core::sync::atomic::AtomicU64;

                        // op == FUTEX_WAIT64
                        if addr % 8 != 0 {
                            return Err(Error::new(EINVAL));
                        }
                        (
                            unsafe { (*(addr as *const AtomicU64)).load(Ordering::SeqCst) },
                            val as u64,
                        )
                    }
                    #[cfg(not(target_has_atomic = "64"))]
                    {
                        return Err(Error::new(crate::syscall::error::EOPNOTSUPP));
                    }
                };
                if fetched != expected {
                    return Err(Error::new(EAGAIN));
                }

                {
                    let mut context = context_lock.write(token.token());

                    context.wake = timeout_opt.map(|TimeSpec { tv_sec, tv_nsec }| {
                        tv_sec as u128 * time::NANOS_PER_SEC + tv_nsec as u128
                    });
                    if let Some((tctl, pctl, _)) = context.sigcontrol() {
                        if tctl.currently_pending_unblocked(pctl) != 0 {
                            return Err(Error::new(EINTR));
                        }
                    }

                    context.block("futex");
                }

                futexes
                    .entry(target_physaddr)
                    .or_insert_with(|| Vec::new())
                    .push(FutexEntry {
                        target_virtaddr,
                        context_lock: context_lock.clone(),
                        addr_space: Arc::downgrade(&current_addrsp),
                    });
            }

            drop(addr_space_guard);

            context::switch(token);

            let context = context_lock.read(token.token());

            // The scheduler clears `wake` on timeout. Hence if a timeout was
            // set and `wake` is now `None`, we timed out.
            if context.wake.is_none() && timeout_opt.is_some() {
                Err(Error::new(ETIMEDOUT))
            } else {
                Ok(0)
            }
        }
        FUTEX_WAKE => {
            let mut woken = 0;

            {
                let mut futexes_map = FUTEXES.lock(token.token());
                let (futexes_map, mut token) = futexes_map.token_split();

                let is_empty = if let Some(futexes) = futexes_map.get_mut(&target_physaddr) {
                    let mut i = 0;
                    let current_addrsp_weak = Arc::downgrade(&current_addrsp);

                    // TODO: Use something like retain, once it is possible to tell it when to stop iterating...
                    while i < futexes.len() && woken < val {
                        if futexes[i].target_virtaddr != target_virtaddr
                            || !current_addrsp_weak.ptr_eq(&futexes[i].addr_space)
                        {
                            i += 1;
                            continue;
                        }
                        futexes[i].context_lock.write(token.token()).unblock();
                        futexes.swap_remove(i);
                        woken += 1;
                    }

                    futexes.is_empty()
                } else {
                    false
                };
                if is_empty {
                    futexes_map.remove(&target_physaddr);
                }
            }

            Ok(woken)
        }
        _ => Err(Error::new(EINVAL)),
    }
}
