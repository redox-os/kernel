#[macro_use]
pub mod macros;

pub mod consts;
pub mod debug;
pub mod device;
pub mod interrupt;
pub mod ipi;
pub mod misc;
pub mod paging;
pub mod rmm;
mod sbi;
pub mod start;
pub mod stop;
pub mod time;

pub use ::rmm::RiscV64Sv48Arch as CurrentRmmArch;
use core::arch::asm;

pub use arch_copy_to_user as arch_copy_from_user;

#[link_section = ".usercopy-fns"]
#[naked]
pub unsafe extern "C" fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    asm!(
        "
        addi   sp, sp, -16
        sd     fp, 0(sp)
        sd     ra, 8(sp)
        addi   fp, sp, 16
        li     t1, 1 << 18 // SUM
        csrs   sstatus, t1
        jal    2f
        csrc   sstatus, t1
        ld     ra, -8(fp)
        ld     fp, -16(fp)
        addi   sp, sp, 16
        ret

    2:  or     t0, a0, a1
        andi   t0, t0, 7
        bne    t0, x0, 4f
        srli   t2, a2, 3
        andi   a2, a2, 7
        beq    t2, x0, 4f
    3:  ld     t0, 0(a1)
        sd     t0, 0(a0)
        addi   a0, a0, 8
        addi   a1, a1, 8
        addi   t2, t2, -1
        bne    t2, x0, 3b

    4:  beq    a2, x0, 5f
        lb     t0, 0(a1)
        sb     t0, 0(a0)
        addi   a0, a0, 1
        addi   a1, a1, 1
        addi   a2, a2, -1
        bne    a2, x0, 4b
    5:  mv     a0, x0
        ret
    ",
        options(noreturn)
    )
}

pub const KFX_SIZE: usize = 1024;

// This function exists as the KFX size is dynamic on x86_64.
pub fn kfx_size() -> usize {
    KFX_SIZE
}
