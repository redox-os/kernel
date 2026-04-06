use core::{
    hint, slice,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    arch::interrupt,
    context,
    context::switch::SwitchResult,
    memory::{PhysicalAddress, RmmA, RmmArch},
    profiling, scheme,
    sync::CleanLockToken,
};

pub mod memory;

#[repr(C, packed(8))]
pub(crate) struct KernelArgs {
    kernel_base: u64,
    kernel_size: u64,

    stack_base: u64,
    stack_size: u64,

    env_base: u64,
    env_size: u64,

    /// The base pointer to the saved RSDP or device tree blob.
    ///
    /// On x86 this field can be NULL, and if so, the system has not booted
    /// with UEFI or in some other way retrieved the RSDPs. The kernel or a
    /// userspace driver will thus try searching the BIOS memory instead. On
    /// UEFI systems, searching is not guaranteed to actually work though.
    /// On other architectures this field must always contain a pointer to
    /// either an RSDP or device tree blob.
    pub(crate) hwdesc_base: u64,
    pub(crate) hwdesc_size: u64,

    areas_base: u64,
    areas_size: u64,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: u64,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: u64,
}

impl KernelArgs {
    pub(crate) fn print(&self) {
        debug!(
            "Kernel: {:X}:{:X}",
            { self.kernel_base },
            self.kernel_base + self.kernel_size
        );
        debug!(
            "Env: {:X}:{:X}",
            { self.env_base },
            self.env_base + self.env_size
        );
        debug!(
            "HWDESC: {:X}:{:X}",
            { self.hwdesc_base },
            self.hwdesc_base + self.hwdesc_size
        );
        debug!(
            "Areas: {:X}:{:X}",
            { self.areas_base },
            self.areas_base + self.areas_size
        );
        debug!(
            "Bootstrap: {:X}:{:X}",
            { self.bootstrap_base },
            self.bootstrap_base + self.bootstrap_size
        );
    }

    pub(crate) fn bootstrap(&self) -> Bootstrap {
        Bootstrap {
            base: crate::memory::Frame::containing(crate::memory::PhysicalAddress::new(
                self.bootstrap_base as usize,
            )),
            page_count: (self.bootstrap_size as usize) / crate::memory::PAGE_SIZE,
            env: self.env(),
        }
    }

    pub(crate) fn env(&self) -> &'static [u8] {
        unsafe {
            slice::from_raw_parts(
                RmmA::phys_to_virt(PhysicalAddress::new(self.env_base as usize)).data()
                    as *const u8,
                self.env_size as usize,
            )
        }
    }

    pub(crate) fn acpi_rsdp(&self) -> Option<*const u8> {
        if self.hwdesc_base != 0 {
            let data = unsafe {
                slice::from_raw_parts(
                    RmmA::phys_to_virt(PhysicalAddress::new(self.hwdesc_base as usize)).data()
                        as *const u8,
                    self.hwdesc_size as usize,
                )
            };
            if data.starts_with(b"RSD PTR ") {
                Some(data.as_ptr())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn dtb(&self) -> Option<fdt::Fdt<'static>> {
        if self.hwdesc_base != 0 {
            let data = unsafe {
                slice::from_raw_parts(
                    RmmA::phys_to_virt(PhysicalAddress::new(self.hwdesc_base as usize)).data()
                        as *const u8,
                    self.hwdesc_size as usize,
                )
            };
            fdt::Fdt::new(data).ok()
        } else {
            None
        }
    }
}

pub(crate) fn init_env() -> &'static [u8] {
    BOOTSTRAP.get().expect("BOOTSTRAP was not set").env
}

extern "C" fn userspace_init() {
    let mut token = unsafe { CleanLockToken::new() };
    let bootstrap = BOOTSTRAP.get().expect("BOOTSTRAP was not set");
    unsafe { crate::syscall::process::usermode_bootstrap(bootstrap, &mut token) }
}

pub(crate) struct Bootstrap {
    pub(crate) base: crate::memory::Frame,
    pub(crate) page_count: usize,
    env: &'static [u8],
}

static BOOTSTRAP: spin::Once<Bootstrap> = spin::Once::new();
pub(crate) static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

/// This is the kernel entry point for the primary CPU. The arch crate is responsible for calling this
pub(crate) fn kmain(bootstrap: Bootstrap) -> ! {
    let mut token = unsafe { CleanLockToken::new() };

    BSP_READY.store(true, Ordering::SeqCst);

    //Initialize the first context, stored in kernel/src/context/mod.rs
    context::init(&mut token);

    //Initialize global schemes, such as `acpi:`.
    scheme::init_globals();

    debug!("BSP: {} CPUs", crate::cpu_count());
    debug!("Env: {:?}", ::core::str::from_utf8(bootstrap.env));

    BOOTSTRAP.call_once(|| bootstrap);

    profiling::ready_for_profiling();

    let owner = None; // kmain not owned by any fd
    match context::spawn(true, owner, userspace_init, &mut token) {
        Ok(context_lock) => {
            let mut context = context_lock.write(token.token());
            context.status = context::Status::Runnable;
            context.name.clear();
            context.name.push_str("[bootstrap]");

            // TODO: Remove these from kernel
            context.euid = 0;
            context.egid = 0;
        }
        Err(err) => {
            panic!("failed to spawn userspace_init: {:?}", err);
        }
    }

    run_userspace(&mut token)
}

/// This is the main kernel entry point for secondary CPUs
#[allow(unreachable_code, unused_variables, dead_code)]
pub(crate) fn kmain_ap(cpu_id: crate::cpu_set::LogicalCpuId) -> ! {
    let mut token = unsafe { CleanLockToken::new() };

    AP_READY.store(true, Ordering::SeqCst);
    while !BSP_READY.load(Ordering::SeqCst) {
        hint::spin_loop();
    }

    #[cfg(feature = "profiling")]
    profiling::maybe_run_profiling_helper_forever(cpu_id);

    if !cfg!(feature = "multi_core") {
        debug!("AP {}: Disabled", cpu_id);

        loop {
            unsafe {
                interrupt::disable();
                interrupt::halt();
            }
        }
    }

    context::init(&mut token);

    debug!("AP {}", cpu_id);

    profiling::ready_for_profiling();

    run_userspace(&mut token);
}

fn run_userspace(token: &mut CleanLockToken) -> ! {
    loop {
        unsafe {
            interrupt::disable();
            match context::switch(token) {
                SwitchResult::Switched => {
                    interrupt::enable_and_nop();
                }
                SwitchResult::AllContextsIdle => {
                    // Enable interrupts, then halt CPU (to save power) until the next interrupt is actually fired.
                    interrupt::enable_and_halt();
                }
            }
        }
    }
}
