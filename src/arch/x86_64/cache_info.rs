use syscall::{Error, EOPNOTSUPP};

use crate::{
    arch::cpuid::cpuid,
    cpu_set::LogicalCpuSet,
    percpu::{all_percpu_blocks, PercpuBlock},
};

/// For details on how to extract cache id, see section 1.4 of
/// this [Intel document](<https://web.archive.org/web/20250313015346/https://cdrdv2-public.intel.com/775917/intel-64-architecture-processor-topology-enumeration.pdf>)
fn init_cache_info_for(percpu: &PercpuBlock) -> syscall::Result<()> {
    let mut l2_cacheid = None;
    let mut l3_cacheid = None;
    let apic_id = percpu.misc_arch_info.apic_id_opt.get().unwrap().get();

    let cache_infos = cpuid()
        .get_cache_parameters()
        .ok_or(Error::new(EOPNOTSUPP))?;

    for cache_info in cache_infos {
        let mask = cache_info.max_cores_for_cache().next_power_of_two() - 1;
        match cache_info.level() {
            1 => (),
            2 => l2_cacheid = Some((apic_id as usize & !mask) as u32),
            3 => l3_cacheid = Some((apic_id as usize & !mask) as u32),
            _ => unreachable!(),
        }
    }

    percpu
        .cache_info
        .l2_cacheid
        .call_once(|| l2_cacheid.unwrap());
    percpu
        .cache_info
        .l3_cacheid
        .call_once(|| l3_cacheid.unwrap());

    Ok(())
}

fn init_cache_domain(percpu: &PercpuBlock) {
    let l2_domain = LogicalCpuSet::empty();
    l2_domain.atomic_set(percpu.cpu_id);

    let l3_domain = LogicalCpuSet::empty();
    l3_domain.atomic_set(percpu.cpu_id);

    let this_l2_cache_id = percpu.cache_info.l2_cacheid.get().unwrap();

    let this_l3_cache_id = percpu.cache_info.l3_cacheid.get().unwrap();

    let l2_siblings = all_percpu_blocks()
        .map(|e| (e.cpu_id, e.cache_info.l2_cacheid.get().unwrap()))
        .filter(|(cpu_id, cache_id)| *cache_id == this_l2_cache_id);

    let l3_siblings = all_percpu_blocks()
        .map(|e| (e.cpu_id, e.cache_info.l3_cacheid.get().unwrap()))
        .filter(|(cpu_id, cache_id)| *cache_id == this_l3_cache_id);

    for (cpu_id, _) in l2_siblings {
        l2_domain.atomic_set(cpu_id);
    }

    for (cpu_id, _) in l3_siblings {
        l3_domain.atomic_set(cpu_id);
    }

    percpu.cache_info.l2_cache_domain.call_once(|| l2_domain);
    percpu.cache_info.l3_cache_domain.call_once(|| l3_domain);
}

pub unsafe fn init() -> syscall::Result<()> {
    if let Some(vendor) = cpuid().get_vendor_info()
        && vendor.as_str() == "GenuineIntel"
    {
        for percpu in all_percpu_blocks() {
            init_cache_info_for(percpu)?;
        }

        for percpu in all_percpu_blocks() {
            init_cache_domain(percpu);
        }

        return Ok(());
    }

    Err(Error::new(EOPNOTSUPP))
}
