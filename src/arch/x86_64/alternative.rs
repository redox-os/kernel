use core::mem::size_of;

use spin::Once;
use x86::controlregs::Cr4;

use crate::context::memory::PageSpan;
use crate::cpuid::{has_ext_feat, cpuid_always};
use crate::paging::{KernelMapper, Page, PageFlags, PAGE_SIZE, VirtualAddress};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AltReloc {
    pub name_start: *const u8,
    pub name_len: usize,
    pub code_start: *mut u8,
    pub origcode_len: usize,
    pub altcode_start: *const u8,
    pub altcode_len: usize,
}

#[cold]
pub unsafe fn early_init(bsp: bool) {
    let relocs_offset = crate::kernel_executable_offsets::__altrelocs_start();
    let relocs_size = crate::kernel_executable_offsets::__altrelocs_end() - relocs_offset;

    assert_eq!(relocs_size % size_of::<AltReloc>(), 0);
    let relocs = core::slice::from_raw_parts(relocs_offset as *const AltReloc, relocs_size / size_of::<AltReloc>());

    let mut enable = KcpuFeatures::empty();

    if cfg!(not(cpu_feature_never = "smap")) && has_ext_feat(|feat| feat.has_smap()) {
        // SMAP (Supervisor-Mode Access Prevention) forbids the kernel from accessing any
        // userspace-accessible pages, with the necessary exception of when RFLAGS.AC = 1. This
        // limits user-memory accesses to the UserSlice wrapper, so that no data outside of
        // usercopy functions can be accidentally accessed by the kernel.
        x86::controlregs::cr4_write(x86::controlregs::cr4() | Cr4::CR4_ENABLE_SMAP);
        // Clear CLAC in (the probably unlikely) case the bootloader set it earlier.
        x86::bits64::rflags::clac();

        enable |= KcpuFeatures::SMAP;
    }

    if cfg!(not(cpu_feature_never = "fsgsbase"))
        && let Some(f) = cpuid_always().get_extended_feature_info()
        && f.has_fsgsbase()
    {
        x86::controlregs::cr4_write(x86::controlregs::cr4() | x86::controlregs::Cr4::CR4_ENABLE_FSGSBASE);

        enable |= KcpuFeatures::FSGSBASE;
    }

    if !bsp {
        return;
    }

    let mut mapper = KernelMapper::lock();
    for reloc in relocs.iter().copied() {
        let name = core::str::from_utf8(core::slice::from_raw_parts(reloc.name_start, reloc.name_len)).expect("invalid feature name");
        let altcode = core::slice::from_raw_parts(reloc.altcode_start, reloc.altcode_len);

        let total_length = core::cmp::max(reloc.altcode_len, reloc.origcode_len);

        let dst_pages = PageSpan::between(
            Page::containing_address(VirtualAddress::new(reloc.code_start as usize)),
            Page::containing_address(VirtualAddress::new((reloc.code_start as usize + reloc.origcode_len).next_multiple_of(PAGE_SIZE))),
        );
        for page in dst_pages.pages() {
            mapper.remap(page.start_address(), PageFlags::new().write(true).execute(true).global(true)).unwrap().flush();
        }

        let code = core::slice::from_raw_parts_mut(reloc.code_start, total_length);

        log::info!("feature {} current {:x?} altcode {:x?}", name, code, altcode);

        let feature_is_enabled = match name {
            "smap" => enable.contains(KcpuFeatures::SMAP),
            "fsgsbase" => enable.contains(KcpuFeatures::FSGSBASE),
            //_ => panic!("unknown altcode relocation: {}", name),
            _ => true,
        };

        if !feature_is_enabled {
            continue;
        }

        let (dst, dst_nops) = code.split_at_mut(reloc.altcode_len);
        dst.copy_from_slice(altcode);

        // XXX: The `.nops` directive only works for constant lengths, and the variable `.skip -X`
        // only outputs the (slower) single-byte 0x90 NOP.

        // This table is from the "Software Optimization Guide for AMD Family 19h Processors" (November
        // 2020).
        const NOPS_TABLE: [&[u8]; 11] = [
            &[0x90],
            &[0x66, 0x90],
            &[0x0f, 0x1f, 0x00],
            &[0x0f, 0x1f, 0x40, 0x00],
            &[0x0f, 0x1f, 0x44, 0x00, 0x00],
            &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
            &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
            &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        for chunk in dst_nops.chunks_mut(NOPS_TABLE.len()) {
            chunk.copy_from_slice(NOPS_TABLE[chunk.len()]);
        }
        log::info!("feature {} new {:x?} altcode {:x?}", name, code, altcode);

        for page in dst_pages.pages() {
            mapper.remap(page.start_address(), PageFlags::new().write(false).execute(true).global(true)).unwrap().flush();
        }
    }
    FEATURES.call_once(|| enable);
}

bitflags! {
    pub struct KcpuFeatures: usize {
        const SMAP = 1;
        const FSGSBASE = 2;
    }
}

static FEATURES: Once<KcpuFeatures> = Once::new();

pub fn features() -> KcpuFeatures {
    *FEATURES.get().expect("early_cpu_init was not called")
}
