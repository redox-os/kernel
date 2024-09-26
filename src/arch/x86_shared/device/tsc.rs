use core::{cell::Cell, ptr::addr_of};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__cpuid;

#[cfg(target_arch = "x86")]
use core::arch::x86::__cpuid;

use rmm::Arch;
use spin::Once;

use crate::{memory::allocate_frame, percpu::PercpuBlock};

struct KvmSupport {
    max_leaf: u32,
    supp_feats: KvmFeatureBits,
}
bitflags! {
    // https://www.kernel.org/doc/html/latest/virt/kvm/x86/cpuid.html
    #[derive(Debug)]
    struct KvmFeatureBits: u32 {
        const CLOCKSOURCE = 1 << 0;
        const CLOCKSOURCE2 = 1 << 3;
        const CLOCKSOURCE_STABLE = 1 << 24;
    }
}

// https://www.kernel.org/doc/html/v5.9/virt/kvm/msr.html
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct PvclockVcpuTimeInfo {
    version: u32,
    pad: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    _pad: [u8; 2],
}

const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b564d01;
const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b564d00;

static KVM_SUPPORT: Once<Option<KvmSupport>> = Once::new();

pub struct TscPercpu {
    vcpu_page: Cell<*const PvclockVcpuTimeInfo>,
    prev: Cell<u128>,
}
impl Default for TscPercpu {
    fn default() -> Self {
        Self {
            vcpu_page: Cell::new(core::ptr::null()),
            prev: Cell::new(0),
        }
    }
}

pub fn monotonic_absolute() -> Option<u128> {
    let inf = &PercpuBlock::current().misc_arch_info.tsc_info;
    let ptr = inf.vcpu_page.get();
    if ptr.is_null() {
        return None;
    }
    loop {
        unsafe {
            let cur_version = addr_of!((*ptr).version).read_volatile();
            if cur_version & 1 == 1 {
                continue;
            }
            let elapsed_ticks =
                x86::time::rdtsc().saturating_sub(addr_of!((*ptr).tsc_timestamp).read_volatile());
            let tsc_shift = addr_of!((*ptr).tsc_shift).read_volatile();
            let elapsed = if tsc_shift >= 0 {
                elapsed_ticks.checked_shl(tsc_shift as u32).unwrap()
            } else {
                elapsed_ticks.checked_shr((-tsc_shift) as u32).unwrap()
            };
            let system_time = addr_of!((*ptr).system_time).read_volatile();
            let tsc_to_system_mul = addr_of!((*ptr).tsc_to_system_mul).read_volatile();
            let new_version = addr_of!((*ptr).version).read_volatile();
            if new_version != cur_version || new_version & 1 == 1 {
                continue;
            }
            let delta = (u128::from(elapsed) * u128::from(tsc_to_system_mul)) >> 32;
            let time = u128::from(system_time) + delta;
            let prev = inf.prev.replace(time);
            if prev > time {
                // TODO
                log::error!("TSC wraparound ({prev} > {time})");
                return None;
            }
            assert!(prev <= time);
            return Some(time);
        }
    }
}

pub unsafe fn init() -> bool {
    let cpuid = crate::cpuid::cpuid();
    if !cpuid.get_feature_info().map_or(false, |f| f.has_tsc()) {
        return false;
    }

    let kvm_support = KVM_SUPPORT.call_once(|| {
        let res = unsafe { __cpuid(0x4000_0000) };
        if [res.ebx, res.ecx, res.edx].map(u32::to_le_bytes) != [*b"KVMK", *b"VMKV", *b"M\0\0\0"] {
            return None;
        }
        let max_leaf = res.eax;
        if max_leaf < 0x4000_0001 {
            return None;
        }
        let res = unsafe { __cpuid(0x4000_0001) };

        let supp_feats = KvmFeatureBits::from_bits_retain(res.eax);

        log::info!("Detected KVM paravirtualization support, features {supp_feats:?}");

        Some(KvmSupport {
            max_leaf,
            supp_feats,
        })
    });

    if let Some(kvm_support) = kvm_support
        && kvm_support
            .supp_feats
            .contains(KvmFeatureBits::CLOCKSOURCE2 | KvmFeatureBits::CLOCKSOURCE_STABLE)
    {
        let frame = allocate_frame().expect("failed to allocate timer page");
        x86::msr::wrmsr(MSR_KVM_SYSTEM_TIME_NEW, (frame.base().data() as u64) | 1);
        let ptr =
            crate::paging::RmmA::phys_to_virt(frame.base()).data() as *const PvclockVcpuTimeInfo;
        PercpuBlock::current()
            .misc_arch_info
            .tsc_info
            .vcpu_page
            .set(ptr);

        /*let tsc_ghz = loop {
            let val1 = ptr.read_volatile();
            let val2 = ptr.read_volatile();
            if val1.version & 1 == 1 || val2.version & 1 == 1 || val1.version != val2.version {
                continue;
            }
            let val1
            break tsc_hz / 1_000_000_000;
        };*/
        true
    } else {
        false
    }
}
