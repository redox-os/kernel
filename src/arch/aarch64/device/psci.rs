use core::{
    arch::asm,
    sync::atomic::{AtomicU8, Ordering},
};

use fdt::Fdt;

const PSCI_VERSION: u32 = 0x8400_0000;
const PSCI_CPU_ON_64: u32 = 0xc400_0003;
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

const CONDUIT_NONE: u8 = 0;
const CONDUIT_HVC: u8 = 1;
const CONDUIT_SMC: u8 = 2;

static CONDUIT: AtomicU8 = AtomicU8::new(CONDUIT_NONE);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Conduit {
    Hvc,
    Smc,
}

impl Conduit {
    fn from_method(method: &str) -> Option<Self> {
        match method {
            "hvc" => Some(Self::Hvc),
            "smc" => Some(Self::Smc),
            _ => None,
        }
    }

    const fn encoded(self) -> u8 {
        match self {
            Self::Hvc => CONDUIT_HVC,
            Self::Smc => CONDUIT_SMC,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Hvc => "hvc",
            Self::Smc => "smc",
        }
    }
}

fn selected_conduit() -> Option<Conduit> {
    match CONDUIT.load(Ordering::Acquire) {
        CONDUIT_HVC => Some(Conduit::Hvc),
        CONDUIT_SMC => Some(Conduit::Smc),
        _ => None,
    }
}

pub(crate) fn available() -> bool {
    selected_conduit().is_some()
}

fn initialize_conduit(conduit: Conduit, source: &str) {
    // Probe PSCI_VERSION before publishing the operations so later calls
    // cannot accidentally use a half-initialized interface.
    let version = unsafe { invoke_with(conduit, PSCI_VERSION, 0, 0, 0) };
    if version < 0 {
        warn!(
            "PSCI_VERSION failed through {} from {} with {}",
            conduit.name(),
            source,
            version
        );
        return;
    }
    let version = version as u32;
    let major = version >> 16;
    let minor = version & 0xffff;
    if major == 0 && minor < 2 {
        warn!(
            "{} claims PSCI v0.2+ but firmware reported {}.{}",
            source, major, minor
        );
        return;
    }

    CONDUIT.store(conduit.encoded(), Ordering::Release);
    info!(
        "PSCI {}.{} using {} conduit from {}",
        major,
        minor,
        conduit.name(),
        source
    );
}

/// Initializes the PSCI v0.2+ conduit described by the device tree.
///
/// PSCI v0.1 used implementation-defined function IDs in DT properties and is
/// intentionally not accepted here. All currently supported Meson64 device
/// trees expose `arm,psci-0.2` or newer and use the standardized IDs.
pub fn init(fdt: &Fdt<'_>) {
    let Some(node) = fdt.find_compatible(&["arm,psci-1.0", "arm,psci-0.2"]) else {
        warn!("PSCI v0.2+ node not found; reset and power-off are unavailable");
        return;
    };

    if node
        .property("status")
        .and_then(|property| property.as_str())
        .is_some_and(|status| status != "ok" && status != "okay")
    {
        warn!("PSCI node is disabled; reset and power-off are unavailable");
        return;
    }

    let Some(method) = node
        .property("method")
        .and_then(|property| property.as_str())
    else {
        warn!("PSCI node has no valid method property");
        return;
    };
    let Some(conduit) = Conduit::from_method(method) else {
        warn!("PSCI node has unsupported method {:?}", method);
        return;
    };

    initialize_conduit(conduit, "device tree");
}

/// Initializes the PSCI conduit described by the ARM boot architecture flags
/// in the ACPI FADT. These fields are at byte offsets 129 and 130 of every FADT
/// revision that supports AArch64.
pub(crate) fn init_acpi() {
    const FADT_ARM_BOOT_ARCH_OFFSET: usize = 129;
    const FADT_ARM_BOOT_ARCH_END: usize = FADT_ARM_BOOT_ARCH_OFFSET + size_of::<u16>();
    const PSCI_COMPLIANT: u16 = 1 << 0;
    const PSCI_USE_HVC: u16 = 1 << 1;

    let fadts = crate::acpi::find_sdt("FACP");
    let fadt = match fadts.as_slice() {
        [] => {
            warn!("ACPI FADT not found; PSCI is unavailable");
            return;
        }
        [fadt] => *fadt,
        _ => {
            warn!(
                "ACPI supplies {} FADTs; PSCI conduit is ambiguous",
                fadts.len()
            );
            return;
        }
    };
    let length = fadt.length as usize;
    if length < FADT_ARM_BOOT_ARCH_END {
        warn!(
            "ACPI FADT is too short for ARM boot architecture flags ({})",
            length
        );
        return;
    }

    let arm_boot_arch = u16::from_le(unsafe {
        ((fadt as *const crate::acpi::sdt::Sdt as *const u8).add(FADT_ARM_BOOT_ARCH_OFFSET)
            as *const u16)
            .read_unaligned()
    });
    if arm_boot_arch & PSCI_COMPLIANT == 0 {
        warn!("ACPI FADT does not advertise PSCI compliance");
        return;
    }

    let conduit = if arm_boot_arch & PSCI_USE_HVC != 0 {
        Conduit::Hvc
    } else {
        Conduit::Smc
    };
    initialize_conduit(conduit, "ACPI FADT");
}

/// Requests PSCI SYSTEM_RESET. A successful firmware call does not return.
pub fn system_reset() -> Result<(), CallError> {
    let result = invoke(PSCI_SYSTEM_RESET, 0, 0, 0)?;
    // SYSTEM_RESET returning, even with zero, violates its success contract.
    Err(CallError::UnexpectedReturn(result))
}

/// Requests PSCI SYSTEM_OFF. A successful firmware call does not return.
pub fn system_off() -> Result<(), CallError> {
    let result = invoke(PSCI_SYSTEM_OFF, 0, 0, 0)?;
    // SYSTEM_OFF has the same non-returning success contract as reset.
    Err(CallError::UnexpectedReturn(result))
}

/// Starts a secondary PE at a physical AArch64 entry point. The caller must
/// provide a context address that remains valid until the secondary has
/// acknowledged it.
pub fn cpu_on(mpidr: u64, entry_phys: usize, context_phys: usize) -> Result<(), CpuOnError> {
    let mpidr = usize::try_from(mpidr).map_err(|_| CpuOnError::InvalidMpidr)?;
    let result =
        invoke(PSCI_CPU_ON_64, mpidr, entry_phys, context_phys).map_err(CpuOnError::Call)?;
    if result == 0 {
        Ok(())
    } else {
        Err(CpuOnError::Firmware(result))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuOnError {
    InvalidMpidr,
    Call(CallError),
    Firmware(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallError {
    Unavailable,
    UnexpectedReturn(i64),
}

fn invoke(function: u32, arg0: usize, arg1: usize, arg2: usize) -> Result<i64, CallError> {
    let conduit = selected_conduit().ok_or(CallError::Unavailable)?;
    Ok(unsafe { invoke_with(conduit, function, arg0, arg1, arg2) })
}

/// Invokes an SMCCC call. PSCI/SMCCC return values are signed and arrive in
/// x0; x1-x3 are treated as clobbered rather than input-only registers.
unsafe fn invoke_with(
    conduit: Conduit,
    function: u32,
    arg0: usize,
    arg1: usize,
    arg2: usize,
) -> i64 {
    let mut result = function as u64;
    unsafe {
        match conduit {
            Conduit::Hvc => asm!(
                "hvc #0",
                inout("x0") result,
                inout("x1") arg0 => _,
                inout("x2") arg1 => _,
                inout("x3") arg2 => _,
                clobber_abi("C"),
                options(nostack),
            ),
            Conduit::Smc => asm!(
                // SMC #0. Use the architectural encoding because LLVM's
                // assembler rejects the mnemonic when the Redox target does
                // not advertise the EL3 feature, even though an EL1 caller is
                // explicitly allowed to trap into firmware through SMC.
                ".inst 0xd4000003",
                inout("x0") result,
                inout("x1") arg0 => _,
                inout("x2") arg1 => _,
                inout("x3") arg2 => _,
                clobber_abi("C"),
                options(nostack),
            ),
        }
    }
    // PSCI v0.2 return codes are signed 32-bit values even for the 64-bit
    // calling convention. Do not rely on firmware to sign-extend w0 into x0.
    result as u32 as i32 as i64
}

#[cfg(test)]
mod tests {
    use super::Conduit;

    #[test]
    fn accepts_only_standard_dt_conduit_names() {
        assert_eq!(Conduit::from_method("smc"), Some(Conduit::Smc));
        assert_eq!(Conduit::from_method("hvc"), Some(Conduit::Hvc));
        assert_eq!(Conduit::from_method("SMC"), None);
        assert_eq!(Conduit::from_method(""), None);
    }
}
