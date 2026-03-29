use core::marker::PhantomData;

use crate::{
    Arch, FrameAllocator, PageEntry, PageFlags, PageFlush, PageTable, PhysicalAddress, TableKind,
    VirtualAddress,
};

pub struct PageMapper<A, F> {
    table_kind: TableKind,
    table_addr: PhysicalAddress,
    allocator: F,
    _phantom: PhantomData<fn() -> A>,
}

impl<A: Arch, F> PageMapper<A, F> {
    unsafe fn new(table_kind: TableKind, table_addr: PhysicalAddress, allocator: F) -> Self {
        Self {
            table_kind,
            table_addr,
            allocator,
            _phantom: PhantomData,
        }
    }

    pub unsafe fn current(table_kind: TableKind, allocator: F) -> Self {
        unsafe {
            let table_addr = A::table(table_kind);
            Self::new(table_kind, table_addr, allocator)
        }
    }

    pub fn is_current(&self) -> bool {
        unsafe { self.table().phys() == A::table(self.table_kind) }
    }

    pub unsafe fn make_current(&self) {
        unsafe {
            A::set_table(self.table_kind, self.table_addr);
        }
    }

    pub fn table(&self) -> PageTable<A> {
        // SAFETY: The only way to initialize a PageMapper is via new(), and we assume it upholds
        // all necessary invariants for this to be safe.
        unsafe { PageTable::new(VirtualAddress::new(0), self.table_addr, A::PAGE_LEVELS - 1) }
    }

    pub fn allocator(&self) -> &F {
        &self.allocator
    }

    pub fn allocator_mut(&mut self) -> &mut F {
        &mut self.allocator
    }

    fn visit<T>(
        &self,
        virt: VirtualAddress,
        f: impl FnOnce(&mut PageTable<A>, usize) -> T,
    ) -> Option<T> {
        let mut table = self.table();
        loop {
            let i = table.index_of(virt)?;
            if table.level() == 0 {
                return Some(f(&mut table, i));
            } else {
                table = unsafe { table.next(i)? };
            }
        }
    }

    pub fn translate(&self, virt: VirtualAddress) -> Option<(PhysicalAddress, PageFlags<A>)> {
        let entry = self.visit(virt, |p1, i| unsafe { p1.entry(i) })??;
        Some((entry.address().ok()?, entry.flags()))
    }

    pub unsafe fn remap_with_full(
        &mut self,
        virt: VirtualAddress,
        f: impl FnOnce(PhysicalAddress, PageFlags<A>) -> Option<(PhysicalAddress, PageFlags<A>)>,
    ) -> Option<(PageFlags<A>, PhysicalAddress, PageFlush<A>)> {
        unsafe {
            self.visit(virt, |p1, i| {
                let old_entry = p1.entry(i)?;
                let old_phys = old_entry.address().ok()?;
                let old_flags = old_entry.flags();
                let Some((new_phys, new_flags)) = f(old_phys, old_flags) else {
                    return None;
                };
                // TODO: Higher-level PageEntry::new interface?
                let new_entry = PageEntry::new(new_phys.data(), new_flags.data());
                p1.set_entry(i, new_entry);
                Some((old_flags, old_phys, PageFlush::new(virt)))
            })
            .flatten()
        }
    }

    pub unsafe fn remap_with(
        &mut self,
        virt: VirtualAddress,
        map_flags: impl FnOnce(PageFlags<A>) -> PageFlags<A>,
    ) -> Option<(PageFlags<A>, PhysicalAddress, PageFlush<A>)> {
        unsafe {
            self.remap_with_full(virt, |same_phys, old_flags| {
                Some((same_phys, map_flags(old_flags)))
            })
        }
    }

    pub unsafe fn remap(
        &mut self,
        virt: VirtualAddress,
        flags: PageFlags<A>,
    ) -> Option<PageFlush<A>> {
        unsafe { self.remap_with(virt, |_| flags).map(|(_, _, flush)| flush) }
    }
}

impl<A: Arch, F: FrameAllocator> PageMapper<A, F> {
    pub unsafe fn create(table_kind: TableKind, mut allocator: F) -> Option<Self> {
        unsafe {
            let table_addr = allocator.allocate_one()?;
            let mut table = Self::new(table_kind, table_addr, allocator);

            match (table_kind, A::KERNEL_SEPARATE_TABLE) {
                (TableKind::Kernel, false) => {
                    // Pre-allocate all kernel top-level page table entries so that when
                    // the page table is copied, these entries are synced between processes.
                    for i in A::PAGE_ENTRIES / 2..A::PAGE_ENTRIES {
                        let phys = table
                            .allocator
                            .allocate_one()
                            .expect("failed to map page table");
                        let flags = A::ENTRY_FLAG_DEFAULT_TABLE;
                        table
                            .table()
                            .set_entry(i, PageEntry::new(phys.data(), flags));
                    }
                }
                (TableKind::User, false) => {
                    // Copy higher half (kernel) mappings
                    let active_ktable = PageMapper::current(TableKind::Kernel, ());
                    for i in A::PAGE_ENTRIES / 2..A::PAGE_ENTRIES {
                        if let Some(entry) = active_ktable.table().entry(i) {
                            table.table().set_entry(i, entry);
                        }
                    }
                }
                (_, true) => {
                    // There is a separate page table for the kernel. No need to copy the kernel
                    // mappings to the user page table.
                }
            }

            Some(table)
        }
    }

    pub unsafe fn map(
        &mut self,
        virt: VirtualAddress,
        flags: PageFlags<A>,
    ) -> Option<PageFlush<A>> {
        unsafe {
            let phys = self.allocator.allocate_one()?;
            self.map_phys(virt, phys, flags)
        }
    }

    pub unsafe fn map_phys(
        &mut self,
        virt: VirtualAddress,
        phys: PhysicalAddress,
        flags: PageFlags<A>,
    ) -> Option<PageFlush<A>> {
        unsafe {
            //TODO: verify virt and phys are aligned
            //TODO: verify flags have correct bits
            let entry = PageEntry::new(phys.data(), flags.data());
            let mut table = self.table();
            loop {
                let i = table.index_of(virt)?;
                if table.level() == 0 {
                    //TODO: check for overwriting entry
                    table.set_entry(i, entry);
                    return Some(PageFlush::new(virt));
                }

                let next = match table.next(i) {
                    Some(some) => some,
                    None => {
                        let next_phys = self.allocator.allocate_one()?;
                        //TODO: correct flags?
                        let flags = A::ENTRY_FLAG_DEFAULT_TABLE
                            | if virt.kind() == TableKind::User {
                                A::ENTRY_FLAG_TABLE_USER
                            } else {
                                0
                            };
                        table.set_entry(i, PageEntry::new(next_phys.data(), flags));
                        table.next(i)?
                    }
                };
                table = next;
            }
        }
    }

    pub unsafe fn map_linearly(
        &mut self,
        phys: PhysicalAddress,
        flags: PageFlags<A>,
    ) -> Option<(VirtualAddress, PageFlush<A>)> {
        unsafe {
            let virt = A::phys_to_virt(phys);
            self.map_phys(virt, phys, flags).map(|flush| (virt, flush))
        }
    }

    pub unsafe fn unmap(&mut self, virt: VirtualAddress) -> Option<PageFlush<A>>
    where
        F: FrameAllocator,
    {
        unsafe {
            let (old, _, flush) = self.unmap_phys(virt)?;
            self.allocator.free_one(old);
            Some(flush)
        }
    }

    pub unsafe fn unmap_phys(
        &mut self,
        virt: VirtualAddress,
    ) -> Option<(PhysicalAddress, PageFlags<A>, PageFlush<A>)> {
        //TODO: verify virt is aligned
        let mut table = self.table();

        let unmap_parents = A::KERNEL_SEPARATE_TABLE || table.index_of(virt)? < A::PAGE_ENTRIES / 2; // Is a userspace mapping

        unsafe {
            unmap_phys_inner(virt, &mut table, unmap_parents, &mut self.allocator)
                .map(|(pa, pf)| (pa, pf, PageFlush::new(virt)))
        }
    }
}

unsafe fn unmap_phys_inner<A: Arch>(
    virt: VirtualAddress,
    table: &mut PageTable<A>,
    unmap_parents: bool,
    allocator: &mut impl FrameAllocator,
) -> Option<(PhysicalAddress, PageFlags<A>)> {
    unsafe {
        let i = table.index_of(virt)?;

        if table.level() == 0 {
            let entry_opt = table.entry(i);
            table.set_entry(i, PageEntry::new(0, 0));
            let entry = entry_opt?;

            return Some((entry.address().ok()?, entry.flags()));
        }

        let mut subtable = table.next(i)?;

        let res = unmap_phys_inner(virt, &mut subtable, unmap_parents, allocator)?;

        if unmap_parents {
            // TODO: Use a counter? This would reduce the remaining number of available bits, but could be
            // faster (benchmark is needed).
            let is_still_populated = (0..A::PAGE_ENTRIES)
                .map(|j| subtable.entry(j).expect("must be within bounds"))
                .any(|e| e.present());

            if !is_still_populated {
                allocator.free_one(subtable.phys());
                table.set_entry(i, PageEntry::new(0, 0));
            }
        }

        Some(res)
    }
}

impl<A, F: core::fmt::Debug> core::fmt::Debug for PageMapper<A, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageMapper")
            .field("frame", &self.table_addr)
            .field("allocator", &self.allocator)
            .finish()
    }
}
