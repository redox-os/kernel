#![allow(unused_imports)]

use core::mem::size_of;

use spin::Once;
use x86::controlregs::{Cr4, Xcr0};

use crate::{
    context::memory::PageSpan,
    cpuid::{cpuid, feature_info, has_ext_feat},
    memory::KernelMapper,
    paging::{Page, PageFlags, VirtualAddress, PAGE_SIZE},
};

#[cfg(all(cpu_feature_never = "xsave", not(cpu_feature_never = "xsaveopt")))]
compile_error!("cannot force-disable xsave without force-disabling xsaveopt");

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AltReloc {
    // These two fields point to a utf-8 name of the feature, see the match statement below.
    pub name_start: *const u8,
    pub name_len: usize,

    // Base address of the code that may later be overwritten.
    pub code_start: *mut u8,
    // Length of the default code, excluding NOPs if the altcode sequence is longer.
    pub origcode_len: usize,
    // Actual length of the overwritable code, i.e. max(origcode_len, altcode_len).
    pub padded_len: usize,
    pub _rsvd: usize,

    // These two fields point to the alternative code (in .rodata), and possible new nop bytes,
    // that will replace the code_start..+padded_len
    pub altcode_start: *const u8,
    pub altcode_len: usize,
}

#[cold]
pub unsafe fn early_init(bsp: bool) {
    let relocs_offset = crate::kernel_executable_offsets::__altrelocs_start();
    let relocs_size = crate::kernel_executable_offsets::__altrelocs_end() - relocs_offset;

    assert_eq!(relocs_size % size_of::<AltReloc>(), 0);
    let relocs = core::slice::from_raw_parts(
        relocs_offset as *const AltReloc,
        relocs_size / size_of::<AltReloc>(),
    );

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
    } else {
        assert!(cfg!(not(cpu_feature_always = "smap")));
    }

    if cfg!(not(cpu_feature_never = "fsgsbase"))
        && let Some(f) = cpuid().get_extended_feature_info()
        && f.has_fsgsbase()
    {
        x86::controlregs::cr4_write(
            x86::controlregs::cr4() | x86::controlregs::Cr4::CR4_ENABLE_FSGSBASE,
        );

        enable |= KcpuFeatures::FSGSBASE;
    } else {
        assert!(cfg!(not(cpu_feature_always = "fsgsbase")));
    }

    #[cfg(not(cpu_feature_never = "xsave"))]
    if feature_info().has_xsave() {
        use raw_cpuid::{ExtendedRegisterStateLocation, ExtendedRegisterType};

        x86::controlregs::cr4_write(
            x86::controlregs::cr4() | x86::controlregs::Cr4::CR4_ENABLE_OS_XSAVE,
        );

        let mut xcr0 = Xcr0::XCR0_FPU_MMX_STATE | Xcr0::XCR0_SSE_STATE;
        x86::controlregs::xcr0_write(xcr0);
        let ext_state_info = cpuid()
            .get_extended_state_info()
            .expect("must be present if XSAVE is supported");

        enable |= KcpuFeatures::XSAVE;
        enable.set(KcpuFeatures::XSAVEOPT, ext_state_info.has_xsaveopt());

        let info = xsave::XsaveInfo {
            ymm_upper_offset: feature_info().has_avx().then(|| {
                xcr0 |= Xcr0::XCR0_AVX_STATE;
                x86::controlregs::xcr0_write(xcr0);

                let state = ext_state_info
                    .iter()
                    .find(|state| {
                        state.register() == ExtendedRegisterType::Avx
                            && state.location() == ExtendedRegisterStateLocation::Xcr0
                    })
                    .expect("CPUID said AVX was supported but there's no state info");

                if state.size() as usize != 16 * core::mem::size_of::<u128>() {
                    log::warn!("Unusual AVX state size {}", state.size());
                }

                state.offset()
            }),
            xsave_size: ext_state_info.xsave_area_size_enabled_features(),
        };
        log::debug!("XSAVE: {:?}", info);

        xsave::XSAVE_INFO.call_once(|| info);
    } else {
        assert!(cfg!(not(cpu_feature_always = "xsave")));
    }

    if !bsp {
        return;
    }

    #[cfg(feature = "self_modifying")]
    overwrite(&relocs, enable);

    #[cfg(not(feature = "self_modifying"))]
    let _ = relocs;

    if cfg!(not(feature = "self_modifying")) {
        assert!(
            cfg!(not(cpu_feature_auto = "smap"))
                && cfg!(not(cpu_feature_auto = "fsgsbase"))
                && cfg!(not(cpu_feature_auto = "xsave"))
                && cfg!(not(cpu_feature_auto = "xsaveopt"))
        );
    }

    FEATURES.call_once(|| enable);
}

#[cfg(feature = "self_modifying")]
unsafe fn overwrite(relocs: &[AltReloc], enable: KcpuFeatures) {
    log::info!("self-modifying features: {:?}", enable);

    let mut mapper = KernelMapper::lock();
    for reloc in relocs.iter().copied() {
        let name = core::str::from_utf8(core::slice::from_raw_parts(
            reloc.name_start,
            reloc.name_len,
        ))
        .expect("invalid feature name");
        let altcode = core::slice::from_raw_parts(reloc.altcode_start, reloc.altcode_len);

        let dst_pages = PageSpan::between(
            Page::containing_address(VirtualAddress::new(reloc.code_start as usize)),
            Page::containing_address(VirtualAddress::new(
                (reloc.code_start as usize + reloc.padded_len).next_multiple_of(PAGE_SIZE),
            )),
        );
        for page in dst_pages.pages() {
            mapper
                .get_mut()
                .unwrap()
                .remap(
                    page.start_address(),
                    PageFlags::new().write(true).execute(true).global(true),
                )
                .unwrap()
                .flush();
        }

        let code = core::slice::from_raw_parts_mut(reloc.code_start, reloc.padded_len);

        log::trace!(
            "feature {} current {:x?} altcode {:x?}",
            name,
            code,
            altcode
        );

        let feature_is_enabled = match name {
            "smap" => enable.contains(KcpuFeatures::SMAP),
            "fsgsbase" => enable.contains(KcpuFeatures::FSGSBASE),
            "xsave" => enable.contains(KcpuFeatures::XSAVE),
            "xsaveopt" => enable.contains(KcpuFeatures::XSAVEOPT),
            //_ => panic!("unknown altcode relocation: {}", name),
            _ => true,
        };

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
            &[
                0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ];

        if feature_is_enabled {
            log::info!("feature {} origcode {:x?}", name, code);
            let (dst, dst_nops) = code.split_at_mut(altcode.len());
            dst.copy_from_slice(altcode);

            for chunk in dst_nops.chunks_mut(NOPS_TABLE.len()) {
                chunk.copy_from_slice(NOPS_TABLE[chunk.len() - 1]);
            }
            log::trace!("feature {} new {:x?} altcode {:x?}", name, code, altcode);
        } else {
            log::trace!("feature !{} origcode {:x?}", name, code);
            let (_, padded) = code.split_at_mut(reloc.origcode_len);

            // Not strictly necessary, but reduces the number of instructions using longer nop
            // instructions.
            for chunk in padded.chunks_mut(NOPS_TABLE.len()) {
                chunk.copy_from_slice(NOPS_TABLE[chunk.len() - 1]);
            }

            log::trace!("feature !{} new {:x?}", name, code);
        }

        for page in dst_pages.pages() {
            mapper
                .get_mut()
                .unwrap()
                .remap(
                    page.start_address(),
                    PageFlags::new().write(false).execute(true).global(true),
                )
                .unwrap()
                .flush();
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct KcpuFeatures: usize {
        const SMAP = 1;
        const FSGSBASE = 2;
        const XSAVE = 4;
        const XSAVEOPT = 8;
    }
}

static FEATURES: Once<KcpuFeatures> = Once::new();

pub fn features() -> KcpuFeatures {
    *FEATURES.get().expect("early_cpu_init was not called")
}

#[cfg(not(cpu_feature_never = "xsave"))]
mod xsave {
    use super::*;

    #[derive(Debug)]
    pub struct XsaveInfo {
        pub ymm_upper_offset: Option<u32>,
        pub xsave_size: u32,
    }
    pub(super) static XSAVE_INFO: Once<XsaveInfo> = Once::new();

    pub fn info() -> Option<&'static XsaveInfo> {
        XSAVE_INFO.get()
    }
}

pub fn kfx_size() -> usize {
    #[cfg(not(cpu_feature_never = "xsave"))]
    {
        match xsave::info() {
            Some(info) => FXSAVE_SIZE + XSAVE_HEADER_SIZE + info.xsave_size as usize,
            None => FXSAVE_SIZE,
        }
    }
    #[cfg(cpu_feature_never = "xsave")]
    {
        // FXSAVE size
        FXSAVE_SIZE
    }
}

pub const FXSAVE_SIZE: usize = 512;
pub const XSAVE_HEADER_SIZE: usize = 64;
