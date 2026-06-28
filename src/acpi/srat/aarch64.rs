use crate::acpi::srat::Srat;

pub fn init_srat(
    allocator: &mut BumpAllocator<A>,
    srat: &Srat,
) -> (&'static [u32], &'static [u32], &'static [NumaMemory]) {
    // todo
}
