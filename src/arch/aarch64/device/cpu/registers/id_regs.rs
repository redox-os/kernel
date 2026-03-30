//! Functions and bitfield definitions for `ID_AA64*` system registers. (e.g. `ID_AA64ISAR0_EL1`)

use core::arch::asm;

bitfield::bitfield! {
    pub struct AA64Isar0(u64);
    impl Debug;
    pub rndr, _: 63, 60;
    pub tlb, _: 59, 56;
    pub ts, _: 55, 52;
    pub fhm, _: 51, 48;
    pub dp, _: 47, 44;
    pub sm4, _: 43, 40;
    pub sm3, _: 39, 36;
    pub sha3, _: 35, 32;
    pub rdm, _: 31, 28;
    pub atomic, _: 23, 20;
    pub crc32, _: 19, 16;
    pub sha2, _: 15, 12;
    pub sha1, _: 11, 8;
    pub aes, _: 7, 4;
}

bitfield::bitfield! {
    pub struct AA64Isar1(u64);
    impl Debug;
    pub ls64, _: 63, 60;
    pub xs, _: 59, 56;
    pub i8mm, _: 55, 52;
    pub dgh, _: 51, 48;
    pub bf16, _: 47, 44;
    pub specres, _: 43, 40;
    pub sb, _: 39, 36;
    pub frintts, _: 35, 32;
    pub gpi, _: 31, 28;
    pub gpa, _: 27, 24;
    pub lrcpc, _: 23, 20;
    pub fcma, _: 19, 16;
    pub jscvt, _: 15, 12;
    pub api, _: 11, 8;
    pub apa, _: 7, 4;
    pub dpb, _: 3, 0;
}

impl AA64Isar0 {
    pub fn has_feat_rng(&self) -> bool {
        self.rndr() == 0b0001
    }
    pub fn has_feat_flagm(&self) -> bool {
        self.ts() == 0b0001
    }
    pub fn has_feat_flagm2(&self) -> bool {
        self.ts() == 0b0010
    }
    pub fn has_feat_fhm(&self) -> bool {
        self.fhm() == 0b0001
    }
    pub fn has_feat_dotprod(&self) -> bool {
        self.dp() == 0b0001
    }
    pub fn has_feat_sm4(&self) -> bool {
        self.sm4() == 0b0001
    }
    pub fn has_feat_sm3(&self) -> bool {
        self.sm3() == 0b0001
    }
    pub fn has_feat_sha3(&self) -> bool {
        self.sha3() == 0b0001
    }
    pub fn has_feat_rdm(&self) -> bool {
        self.rdm() == 0b0001
    }
    pub fn has_feat_lse(&self) -> bool {
        self.atomic() == 0b0010
    }
    pub fn has_feat_lse128(&self) -> bool {
        self.atomic() == 0b0011
    }
    /// The current Arm Architecture Registers Manual calls it FEAT_CRC32,
    /// but everyone else seems to call it FEAT_CRC.
    pub fn has_feat_crc(&self) -> bool {
        self.crc32() == 0b0001
    }
    pub fn has_feat_sha256(&self) -> bool {
        self.sha2() == 0b0001
    }
    pub fn has_feat_sha512(&self) -> bool {
        self.sha2() == 0b0010
    }
    pub fn has_feat_sha1(&self) -> bool {
        self.sha1() == 0b0001
    }
    pub fn has_feat_aes(&self) -> bool {
        self.aes() == 0b0001
    }
    pub fn has_feat_pmull(&self) -> bool {
        self.aes() == 0b0010
    }
}

impl AA64Isar1 {
    pub fn has_feat_i8mm(&self) -> bool {
        self.i8mm() == 0b0001
    }
    pub fn has_feat_bf16(&self) -> bool {
        self.bf16() == 0b0001
    }
    pub fn has_feat_sb(&self) -> bool {
        self.sb() == 0b0001
    }
    pub fn has_feat_frintts(&self) -> bool {
        self.frintts() == 0b0001
    }
    pub fn has_feat_lrcpc(&self) -> bool {
        self.lrcpc() == 0b0001
    }
    pub fn has_feat_lrcpc2(&self) -> bool {
        self.lrcpc() == 0b0010
    }
    pub fn has_feat_lrcpc3(&self) -> bool {
        self.lrcpc() == 0b0011
    }
    pub fn has_feat_fcma(&self) -> bool {
        self.fcma() == 0b0001
    }
    pub fn has_feat_jscvt(&self) -> bool {
        self.jscvt() == 0b0011
    }
    pub fn has_feat_dpb(&self) -> bool {
        self.dpb() == 0b0001
    }
    pub fn has_feat_dpb2(&self) -> bool {
        self.dpb() == 0b0010
    }
}

pub fn aa64isar0() -> AA64Isar0 {
    let ret: u64;
    unsafe {
        asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) ret);
    }
    AA64Isar0(ret)
}

pub fn aa64isar1() -> AA64Isar1 {
    let ret: u64;
    unsafe {
        asm!("mrs {}, ID_AA64ISAR1_EL1", out(reg) ret);
    }
    AA64Isar1(ret)
}
