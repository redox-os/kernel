use alloc::vec::Vec;
use core::fmt;

use fdt::{node::FdtNode, Fdt};
use spin::Once;

use crate::cpu_set::MAX_CPU_COUNT;

use super::registers::control_regs;

// Aff3 is at bits 39:32; Aff2:Aff0 are at bits 23:0. The remaining MPIDR
// fields describe properties of the executing PE and must not occur in a DT
// CPU reg value. This is MPIDR_HWID_BITMASK in Linux arm64.
pub(super) const MPIDR_HWID_MASK: u64 = 0x0000_00ff_00ff_ffff;

static TOPOLOGY: Once<Vec<CpuDescription>> = Once::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EnableMethod {
    None,
    Psci,
    Unsupported,
}

impl EnableMethod {
    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Psci => "psci",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CpuDescription {
    pub(super) mpidr: u64,
    pub(super) boot_cpu: bool,
    pub(super) enable_method: EnableMethod,
}

struct DiscoveredTopology {
    cpus: Vec<CpuDescription>,
    disabled: usize,
}

#[derive(Debug, Eq, PartialEq)]
enum TopologyError<'a> {
    MissingCpusNode,
    InvalidAddressCells,
    InvalidSizeCells,
    NoEnabledCpus,
    TooManyCpus(usize),
    InvalidDeviceType(&'a str),
    MissingReg(&'a str),
    InvalidReg(&'a str),
    InvalidMpidr { node: &'a str, mpidr: u64 },
    DuplicateMpidr(u64),
    BootCpuMissing(u64),
}

impl fmt::Display for TopologyError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingCpusNode => write!(f, "missing /cpus node"),
            Self::InvalidAddressCells => write!(f, "/cpus has invalid #address-cells"),
            Self::InvalidSizeCells => write!(f, "/cpus must have #size-cells = 0"),
            Self::NoEnabledCpus => write!(f, "/cpus has no enabled CPU nodes"),
            Self::TooManyCpus(count) => write!(
                f,
                "/cpus describes {} enabled CPUs, kernel limit is {}",
                count, MAX_CPU_COUNT
            ),
            Self::InvalidDeviceType(node) => {
                write!(f, "CPU node {:?} has invalid device_type", node)
            }
            Self::MissingReg(node) => write!(f, "CPU node {:?} has no reg property", node),
            Self::InvalidReg(node) => write!(f, "CPU node {:?} has invalid reg property", node),
            Self::InvalidMpidr { node, mpidr } => {
                write!(f, "CPU node {:?} has invalid MPIDR {:#x}", node, mpidr)
            }
            Self::DuplicateMpidr(mpidr) => write!(f, "duplicate CPU MPIDR {:#x}", mpidr),
            Self::BootCpuMissing(mpidr) => {
                write!(f, "boot CPU MPIDR {:#x} is absent or disabled", mpidr)
            }
        }
    }
}

fn property_u32(node: FdtNode<'_, '_>, name: &str) -> Option<u32> {
    let bytes: [u8; 4] = node.property(name)?.value.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn parse_mpidr(reg: &[u8], address_cells: usize) -> Option<u64> {
    match address_cells {
        1 => Some(u32::from_be_bytes(reg.try_into().ok()?) as u64),
        2 => Some(u64::from_be_bytes(reg.try_into().ok()?)),
        _ => None,
    }
}

fn enabled(node: FdtNode<'_, '_>) -> bool {
    match node.property("status") {
        None => true,
        Some(status) => matches!(status.as_str(), Some("ok" | "okay")),
    }
}

fn enable_method(node: FdtNode<'_, '_>) -> EnableMethod {
    match node.property("enable-method") {
        None => EnableMethod::None,
        Some(method) => match method.as_str() {
            Some("psci") => EnableMethod::Psci,
            _ => EnableMethod::Unsupported,
        },
    }
}

fn discover<'b, 'a: 'b>(
    fdt: &'b Fdt<'a>,
    boot_mpidr: u64,
) -> Result<DiscoveredTopology, TopologyError<'a>> {
    let cpus_node = fdt
        .find_node("/cpus")
        .ok_or(TopologyError::MissingCpusNode)?;
    let address_cells = property_u32(cpus_node, "#address-cells")
        .filter(|cells| matches!(cells, 1 | 2))
        .ok_or(TopologyError::InvalidAddressCells)? as usize;
    if property_u32(cpus_node, "#size-cells") != Some(0) {
        return Err(TopologyError::InvalidSizeCells);
    }

    let mut cpus = Vec::new();
    let mut disabled = 0;
    for node in cpus_node
        .children()
        .filter(|node| node.name.split('@').next() == Some("cpu"))
    {
        // Do not derive the PE identity from `compatible`: some vendor DTs
        // label these nodes differently from the MIDR implemented by the
        // silicon. `device_type`, reg/MPIDR and enable-method define the boot
        // topology; MIDR_EL1 remains authoritative for the CPU model.
        if node
            .property("device_type")
            .and_then(|value| value.as_str())
            != Some("cpu")
        {
            return Err(TopologyError::InvalidDeviceType(node.name));
        }
        if !enabled(node) {
            disabled += 1;
            continue;
        }

        let reg = node
            .property("reg")
            .ok_or(TopologyError::MissingReg(node.name))?;
        let mpidr =
            parse_mpidr(reg.value, address_cells).ok_or(TopologyError::InvalidReg(node.name))?;
        if mpidr & !MPIDR_HWID_MASK != 0 {
            return Err(TopologyError::InvalidMpidr {
                node: node.name,
                mpidr,
            });
        }
        if cpus.iter().any(|cpu: &CpuDescription| cpu.mpidr == mpidr) {
            return Err(TopologyError::DuplicateMpidr(mpidr));
        }
        if cpus.len() >= MAX_CPU_COUNT as usize {
            return Err(TopologyError::TooManyCpus(cpus.len() + 1));
        }

        cpus.push(CpuDescription {
            mpidr,
            boot_cpu: mpidr == boot_mpidr,
            enable_method: enable_method(node),
        });
    }

    if cpus.is_empty() {
        return Err(TopologyError::NoEnabledCpus);
    }
    let boot_index = cpus
        .iter()
        .position(|cpu| cpu.boot_cpu)
        .ok_or(TopologyError::BootCpuMissing(boot_mpidr))?;

    // Logical CPU zero is always the already-running BSP, independent of DT
    // child ordering. Future CPU_ON code may assign logical IDs from this
    // array without relying on a board-specific node order.
    cpus.swap(0, boot_index);

    Ok(DiscoveredTopology { cpus, disabled })
}

pub(super) fn init(fdt: &Fdt<'_>) -> Option<&'static [CpuDescription]> {
    let boot_mpidr = unsafe { control_regs::mpidr() } & MPIDR_HWID_MASK;
    let discovered = match discover(fdt, boot_mpidr) {
        Ok(topology) => topology,
        Err(error) => {
            warn!("CPU topology unavailable: {}", error);
            return None;
        }
    };

    let disabled = discovered.disabled;
    let topology = TOPOLOGY.call_once(|| discovered.cpus);
    let psci_secondaries = topology
        .iter()
        .filter(|cpu| !cpu.boot_cpu && cpu.enable_method == EnableMethod::Psci)
        .count();

    info!(
        "CPU topology: {} enabled, {} disabled, BSP MPIDR={:#x}, {} PSCI secondaries",
        topology.len(),
        disabled,
        boot_mpidr,
        psci_secondaries
    );
    for (logical_id, cpu) in topology.iter().enumerate() {
        debug!(
            "CPU topology logical #{}: MPIDR={:#x} boot={} enable-method={}",
            logical_id,
            cpu.mpidr,
            cpu.boot_cpu,
            cpu.enable_method.name()
        );
    }

    Some(topology.as_slice())
}

pub(super) fn summary() -> Option<(usize, usize)> {
    let topology = TOPOLOGY.get()?;
    let psci_secondaries = topology
        .iter()
        .filter(|cpu| !cpu.boot_cpu && cpu.enable_method == EnableMethod::Psci)
        .count();
    Some((topology.len(), psci_secondaries))
}

#[cfg(test)]
mod tests {
    use super::{parse_mpidr, CpuDescription, EnableMethod, MPIDR_HWID_MASK};

    #[test]
    fn parses_one_and_two_cell_mpidrs() {
        assert_eq!(parse_mpidr(&[0, 0, 0, 3], 1), Some(3));
        assert_eq!(
            parse_mpidr(&[0, 0, 0, 1, 0, 0, 0, 2], 2),
            Some(0x1_0000_0002)
        );
        assert_eq!(parse_mpidr(&[0, 0, 0, 1], 2), None);
    }

    #[test]
    fn hardware_mask_contains_all_four_affinity_levels_only() {
        assert_eq!(MPIDR_HWID_MASK, 0xff00_ffff_ff);
        assert_eq!(0x12_0034_5678 & !MPIDR_HWID_MASK, 0);
        assert_ne!(0x8000_0000 & !MPIDR_HWID_MASK, 0);
    }

    #[test]
    fn cpu_description_distinguishes_online_bsp_from_psci_candidate() {
        let bsp = CpuDescription {
            mpidr: 0,
            boot_cpu: true,
            enable_method: EnableMethod::Psci,
        };
        let secondary = CpuDescription {
            mpidr: 1,
            boot_cpu: false,
            enable_method: EnableMethod::Psci,
        };
        assert!(bsp.boot_cpu);
        assert!(!secondary.boot_cpu);
    }
}
