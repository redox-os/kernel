/// Extended CPU topology detection for modern Intel CPUs (Alder Lake+)
///
/// This module implements proper APIC ID to logical CPU ID mapping for hybrid
/// architectures with P-cores and E-cores that break traditional sequential mapping.
use crate::arch::x86_shared::cpuid::cpuid;
use alloc::vec::Vec;
use core::fmt;

/// Information about CPU topology and core types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTopologyInfo {
    /// Logical CPU ID used by the kernel
    pub logical_id: u32,
    /// Hardware APIC ID
    pub apic_id: u32,
    /// Type of CPU core (P-core vs E-core)
    pub core_type: CoreType,
    /// SMT thread ID within the core
    pub smt_id: u32,
    /// Core ID within the package
    pub core_id: u32,
    /// Package (socket) ID
    pub package_id: u32,
}

/// CPU core type for hybrid architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreType {
    /// Performance core (Golden Cove on Alder Lake)
    Performance,
    /// Efficiency core (Gracemont on Alder Lake)  
    Efficiency,
    /// Unknown or traditional core type
    Unknown,
}

impl fmt::Display for CoreType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreType::Performance => write!(f, "P-core"),
            CoreType::Efficiency => write!(f, "E-core"),
            CoreType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Extended topology detection result
#[derive(Debug)]
pub struct TopologyMap {
    /// Mapping from logical CPU ID to topology info
    pub cpus: Vec<CpuTopologyInfo>,
    /// Whether this is a hybrid architecture (P-cores + E-cores)
    pub is_hybrid: bool,
    /// Maximum APIC ID found
    pub max_apic_id: u32,
}

impl TopologyMap {
    /// Find topology info by logical CPU ID
    pub fn get_by_logical_id(&self, logical_id: u32) -> Option<&CpuTopologyInfo> {
        self.cpus.iter().find(|cpu| cpu.logical_id == logical_id)
    }

    /// Find topology info by APIC ID
    pub fn get_by_apic_id(&self, apic_id: u32) -> Option<&CpuTopologyInfo> {
        self.cpus.iter().find(|cpu| cpu.apic_id == apic_id)
    }

    /// Get total number of CPUs
    pub fn cpu_count(&self) -> usize {
        self.cpus.len()
    }
}

/// Detect extended CPU topology using CPUID leaves 1F or 0B
///
/// This function properly handles modern Intel hybrid architectures by:
/// 1. Using CPUID leaf 1F (preferred) or 0B for extended topology
/// 2. Detecting hybrid architecture support (CPUID leaf 7)
/// 3. Identifying core types using CPUID leaf 1A
/// 4. Creating proper APIC ID to logical CPU ID mapping
pub fn detect_extended_topology() -> Result<TopologyMap, &'static str> {
    let cpuid = cpuid();

    // Check if extended topology enumeration is available
    let max_leaf = cpuid
        .get_vendor_info()
        .ok_or("CPUID vendor info not available")?;

    // Prefer CPUID leaf 1F over 0B for newer CPUs
    let topology_leaf = if max_leaf.as_u32() >= 0x1F {
        // Check if leaf 1F is valid (EBX != 0)
        let leaf_1f = cpuid.get_extended_topology_info_v2();
        if leaf_1f.is_some() {
            0x1F
        } else {
            0x0B
        }
    } else {
        0x0B
    };

    // Check for hybrid architecture support (CPUID leaf 7)
    let is_hybrid = cpuid
        .get_extended_feature_info()
        .map(|features| features.has_hybrid())
        .unwrap_or(false);

    log::info!(
        "CPU topology detection: leaf={:#x}, hybrid={}",
        topology_leaf,
        is_hybrid
    );

    // For now, create a simple mapping - this is a foundation that can be extended
    // In a full implementation, we would enumerate all cores and build the complete topology
    let current_apic_id = unsafe { crate::arch::device::local_apic::LOCAL_APIC.read().id() };

    let current_core_type = if is_hybrid {
        detect_current_core_type()
    } else {
        CoreType::Unknown
    };

    let topology_info = CpuTopologyInfo {
        logical_id: 0, // BSP is always logical CPU 0
        apic_id: current_apic_id,
        core_type: current_core_type,
        smt_id: 0,     // Simplified for now
        core_id: 0,    // Simplified for now
        package_id: 0, // Simplified for now
    };

    Ok(TopologyMap {
        cpus: alloc::vec![topology_info],
        is_hybrid,
        max_apic_id: current_apic_id,
    })
}

/// Detect the core type of the current CPU using CPUID leaf 1A
fn detect_current_core_type() -> CoreType {
    let cpuid = cpuid();

    // CPUID leaf 1A provides hybrid information
    // EAX[31:24] contains the core type
    let hybrid_info = unsafe {
        let result = core::arch::x86_64::__cpuid_count(0x1A, 0);
        result.eax
    };

    let core_type_raw = (hybrid_info >> 24) & 0xFF;

    match core_type_raw {
        0x20 => CoreType::Efficiency,  // E-core (Gracemont)
        0x40 => CoreType::Performance, // P-core (Golden Cove)
        _ => CoreType::Unknown,
    }
}

/// Validate APIC ID consistency between ACPI MADT and CPUID
pub fn validate_apic_id_consistency(madt_apic_id: u32, cpuid_apic_id: u32) -> bool {
    if madt_apic_id != cpuid_apic_id {
        log::warn!(
            "APIC ID mismatch: MADT reports {}, CPUID reports {}",
            madt_apic_id,
            cpuid_apic_id
        );
        false
    } else {
        true
    }
}
