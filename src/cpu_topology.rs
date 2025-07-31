/// Global CPU topology management for multi-core support
///
/// This module provides a centralized way to manage CPU topology information,
/// especially for modern hybrid architectures like Intel Alder Lake.
use crate::cpu_set::LogicalCpuId;
use alloc::vec::Vec;
use spin::Mutex;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::arch::x86_shared::topology::{CoreType, CpuTopologyInfo, TopologyMap};

/// Global CPU topology information
static CPU_TOPOLOGY: Mutex<Option<CpuTopologyData>> = Mutex::new(None);

/// CPU topology data for the entire system
#[derive(Debug)]
pub struct CpuTopologyData {
    /// Per-CPU topology information
    pub cpus: Vec<CpuTopologyInfo>,
    /// Whether this system has hybrid architecture
    pub is_hybrid: bool,
    /// Total number of CPUs detected
    pub total_cpus: usize,
    /// Number of Performance cores
    pub p_core_count: usize,
    /// Number of Efficiency cores  
    pub e_core_count: usize,
}

impl CpuTopologyData {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn from_topology_map(map: TopologyMap) -> Self {
        let p_core_count = map
            .cpus
            .iter()
            .filter(|cpu| cpu.core_type == CoreType::Performance)
            .count();
        let e_core_count = map
            .cpus
            .iter()
            .filter(|cpu| cpu.core_type == CoreType::Efficiency)
            .count();

        Self {
            total_cpus: map.cpu_count(),
            is_hybrid: map.is_hybrid,
            p_core_count,
            e_core_count,
            cpus: map.cpus,
        }
    }
}

/// Initialize CPU topology detection
///
/// This should be called early in kernel initialization to detect
/// the CPU topology and set up proper APIC ID mapping.
pub fn init_cpu_topology() -> Result<(), &'static str> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let topology_map = crate::arch::x86_shared::topology::detect_extended_topology()?;

        log::info!("CPU Topology detected:");
        log::info!("  Total CPUs: {}", topology_map.cpu_count());
        log::info!("  Hybrid architecture: {}", topology_map.is_hybrid);
        log::info!("  Max APIC ID: {}", topology_map.max_apic_id);

        if topology_map.is_hybrid {
            let p_cores = topology_map
                .cpus
                .iter()
                .filter(|cpu| cpu.core_type == CoreType::Performance)
                .count();
            let e_cores = topology_map
                .cpus
                .iter()
                .filter(|cpu| cpu.core_type == CoreType::Efficiency)
                .count();
            log::info!("  P-cores: {}, E-cores: {}", p_cores, e_cores);
        }

        let topology_data = CpuTopologyData::from_topology_map(topology_map);
        *CPU_TOPOLOGY.lock() = Some(topology_data);

        Ok(())
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        log::info!("CPU topology detection not implemented for this architecture");
        Ok(())
    }
}

/// Get APIC ID for a given logical CPU ID
///
/// This is critical for multi-core initialization where we need to send
/// IPIs to specific cores using their APIC IDs.
pub fn get_apic_id_for_logical_cpu(logical_id: LogicalCpuId) -> Option<u32> {
    let topology = CPU_TOPOLOGY.lock();
    if let Some(ref data) = *topology {
        data.cpus
            .iter()
            .find(|cpu| cpu.logical_id == logical_id.get())
            .map(|cpu| cpu.apic_id)
    } else {
        None
    }
}

/// Get logical CPU ID for a given APIC ID
///
/// This is used when an AP (Application Processor) starts up and needs
/// to determine its logical CPU ID from its APIC ID.
pub fn get_logical_cpu_for_apic_id(apic_id: u32) -> Option<LogicalCpuId> {
    let topology = CPU_TOPOLOGY.lock();
    if let Some(ref data) = *topology {
        data.cpus
            .iter()
            .find(|cpu| cpu.apic_id == apic_id)
            .map(|cpu| LogicalCpuId::new(cpu.logical_id))
    } else {
        None
    }
}

/// Check if the current system has hybrid architecture
pub fn is_hybrid_architecture() -> bool {
    let topology = CPU_TOPOLOGY.lock();
    topology
        .as_ref()
        .map(|data| data.is_hybrid)
        .unwrap_or(false)
}

/// Get the core type for a given logical CPU ID
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_core_type(logical_id: LogicalCpuId) -> Option<CoreType> {
    let topology = CPU_TOPOLOGY.lock();
    if let Some(ref data) = *topology {
        data.cpus
            .iter()
            .find(|cpu| cpu.logical_id == logical_id.get())
            .map(|cpu| cpu.core_type)
    } else {
        None
    }
}

/// Validate that an APIC ID from ACPI matches our detected topology
///
/// This helps catch firmware bugs or inconsistencies between ACPI
/// and CPUID-reported topology information.
pub fn validate_acpi_apic_id(acpi_apic_id: u32) -> bool {
    let topology = CPU_TOPOLOGY.lock();
    if let Some(ref data) = *topology {
        data.cpus.iter().any(|cpu| cpu.apic_id == acpi_apic_id)
    } else {
        // If topology not initialized, assume valid (fallback behavior)
        true
    }
}
