use std::{collections::BTreeMap, marker::PhantomData, mem, ptr, sync::Mutex};

use crate::{
    arch::x86_64::X8664Arch, page::PageFlags, Arch, MemoryArea, PageEntry, PhysicalAddress,
    TableKind, VirtualAddress, MEGABYTE,
};

#[derive(Clone, Copy)]
pub struct EmulateArch;

impl Arch for EmulateArch {
    const PAGE_SHIFT: usize = X8664Arch::PAGE_SHIFT;
    const PAGE_ENTRY_SHIFT: usize = X8664Arch::PAGE_ENTRY_SHIFT;
    const PAGE_LEVELS: usize = X8664Arch::PAGE_LEVELS;

    const ENTRY_ADDRESS_SHIFT: usize = X8664Arch::ENTRY_ADDRESS_SHIFT;
    const ENTRY_FLAG_DEFAULT_PAGE: usize = X8664Arch::ENTRY_FLAG_DEFAULT_PAGE;
    const ENTRY_FLAG_DEFAULT_TABLE: usize = X8664Arch::ENTRY_FLAG_DEFAULT_TABLE;
    const ENTRY_FLAG_PRESENT: usize = X8664Arch::ENTRY_FLAG_PRESENT;
    const ENTRY_FLAG_READONLY: usize = X8664Arch::ENTRY_FLAG_READONLY;
    const ENTRY_FLAG_READWRITE: usize = X8664Arch::ENTRY_FLAG_READWRITE;
    const ENTRY_FLAG_PAGE_USER: usize = X8664Arch::ENTRY_FLAG_PAGE_USER;
    const ENTRY_FLAG_NO_EXEC: usize = X8664Arch::ENTRY_FLAG_NO_EXEC;
    const ENTRY_FLAG_EXEC: usize = X8664Arch::ENTRY_FLAG_EXEC;

    const PHYS_OFFSET: usize = X8664Arch::PHYS_OFFSET;

    const ENTRY_FLAG_GLOBAL: usize = X8664Arch::ENTRY_FLAG_GLOBAL;
    const ENTRY_FLAG_NO_GLOBAL: usize = X8664Arch::ENTRY_FLAG_NO_GLOBAL;

    const ENTRY_ADDRESS_WIDTH: usize = X8664Arch::ENTRY_ADDRESS_WIDTH;

    const ENTRY_FLAG_WRITE_COMBINING: usize = X8664Arch::ENTRY_FLAG_WRITE_COMBINING;

    unsafe fn init() -> &'static [MemoryArea] {
        unsafe {
            // Create machine with PAGE_ENTRIES pages offset mapped (2 MiB on x86_64)
            let mut machine = Machine::new(MEMORY_SIZE);

            // PML4 index 256 (PHYS_OFFSET) link to PDP
            let pml4 = 0;
            let pdp = pml4 + Self::PAGE_SIZE;
            let flags = Self::ENTRY_FLAG_READWRITE | Self::ENTRY_FLAG_PRESENT;
            machine.write_phys::<usize>(
                PhysicalAddress::new(pml4 + 256 * Self::PAGE_ENTRY_SIZE),
                pdp | flags,
            );

            // PDP link to PD
            let pd = pdp + Self::PAGE_SIZE;
            machine.write_phys::<usize>(PhysicalAddress::new(pdp), pd | flags);

            // PD link to PT
            let pt = pd + Self::PAGE_SIZE;
            machine.write_phys::<usize>(PhysicalAddress::new(pd), pt | flags);

            // PT links to frames
            for i in 0..Self::PAGE_ENTRIES {
                let page = i * Self::PAGE_SIZE;
                machine.write_phys::<usize>(
                    PhysicalAddress::new(pt + i * Self::PAGE_ENTRY_SIZE),
                    page | flags,
                );
            }

            *MACHINE.lock().unwrap() = Some(machine);

            // Set table to pml4
            EmulateArch::set_table(TableKind::Kernel, PhysicalAddress::new(pml4));

            &MEMORY_AREAS
        }
    }

    #[inline(always)]
    unsafe fn read<T>(address: VirtualAddress) -> T {
        MACHINE.lock().unwrap().as_ref().unwrap().read(address)
    }

    #[inline(always)]
    unsafe fn write<T>(address: VirtualAddress, value: T) {
        MACHINE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .write(address, value)
    }

    #[inline(always)]
    unsafe fn write_bytes(address: VirtualAddress, value: u8, count: usize) {
        MACHINE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .write_bytes(address, value, count)
    }

    #[inline(always)]
    unsafe fn invalidate(address: VirtualAddress) {
        MACHINE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .invalidate(address);
    }

    #[inline(always)]
    unsafe fn invalidate_all() {
        MACHINE.lock().unwrap().as_mut().unwrap().invalidate_all();
    }

    #[inline(always)]
    unsafe fn table(_table_kind: TableKind) -> PhysicalAddress {
        MACHINE.lock().unwrap().as_mut().unwrap().get_table()
    }

    #[inline(always)]
    unsafe fn set_table(_table_kind: TableKind, address: PhysicalAddress) {
        MACHINE.lock().unwrap().as_mut().unwrap().set_table(address);
    }
    fn virt_is_valid(_address: VirtualAddress) -> bool {
        // TODO: Don't see why an emulated arch would have any problems with canonicalness...
        true
    }
}

const MEMORY_SIZE: usize = 64 * MEGABYTE;
static MEMORY_AREAS: [MemoryArea; 2] = [
    MemoryArea {
        base: PhysicalAddress::new(EmulateArch::PAGE_SIZE * 4), // Initial PML4, PDP, PD, and PT wasted
        size: MEMORY_SIZE / 2 - EmulateArch::PAGE_SIZE * 4,
    },
    // Second area for debugging
    MemoryArea {
        base: PhysicalAddress::new(MEMORY_SIZE / 2),
        size: MEMORY_SIZE / 2,
    },
];

static MACHINE: Mutex<Option<Machine<EmulateArch>>> = Mutex::new(None);

struct Machine<A> {
    memory: Box<[u8]>,
    map: BTreeMap<VirtualAddress, PageEntry<A>>,
    table_addr: PhysicalAddress,
    phantom: PhantomData<A>,
}

impl<A: Arch> Machine<A> {
    fn new(memory_size: usize) -> Self {
        Self {
            memory: vec![0; memory_size].into_boxed_slice(),
            map: BTreeMap::new(),
            table_addr: PhysicalAddress::new(0),
            phantom: PhantomData,
        }
    }

    fn read_phys<T>(&self, phys: PhysicalAddress) -> T {
        let size = mem::size_of::<T>();
        if phys.add(size).data() <= self.memory.len() {
            unsafe { ptr::read(self.memory.as_ptr().add(phys.data()) as *const T) }
        } else {
            panic!(
                "read_phys: 0x{:X} size 0x{:X} outside of memory",
                phys.data(),
                size
            );
        }
    }

    fn write_phys<T>(&mut self, phys: PhysicalAddress, value: T) {
        let size = mem::size_of::<T>();
        if phys.add(size).data() <= self.memory.len() {
            unsafe {
                ptr::write(self.memory.as_mut_ptr().add(phys.data()) as *mut T, value);
            }
        } else {
            panic!(
                "write_phys: 0x{:X} size 0x{:X} outside of memory",
                phys.data(),
                size
            );
        }
    }

    fn write_phys_bytes(&mut self, phys: PhysicalAddress, value: u8, count: usize) {
        if phys.add(count).data() <= self.memory.len() {
            unsafe {
                ptr::write_bytes(self.memory.as_mut_ptr().add(phys.data()), value, count);
            }
        } else {
            panic!(
                "write_phys_bytes: 0x{:X} count 0x{:X} outside of memory",
                phys.data(),
                count
            );
        }
    }

    fn translate(&self, virt: VirtualAddress) -> Option<(PhysicalAddress, PageFlags<A>)> {
        let virt_data = virt.data();
        let page = virt_data & A::PAGE_ADDRESS_MASK;
        let offset = virt_data & A::PAGE_OFFSET_MASK;
        let entry = self.map.get(&VirtualAddress::new(page))?;
        Some((entry.address().ok()?.add(offset), entry.flags()))
    }

    fn read<T>(&self, virt: VirtualAddress) -> T {
        //TODO: allow reading past page boundaries
        let virt_data = virt.data();
        let size = mem::size_of::<T>();
        if (virt_data & A::PAGE_ADDRESS_MASK) != ((virt_data + (size - 1)) & A::PAGE_ADDRESS_MASK) {
            panic!(
                "read: 0x{:X} size 0x{:X} passes page boundary",
                virt_data, size
            );
        }

        if let Some((phys, _flags)) = self.translate(virt) {
            self.read_phys(phys)
        } else {
            panic!("read: 0x{:X} size 0x{:X} not present", virt_data, size);
        }
    }

    fn write<T>(&mut self, virt: VirtualAddress, value: T) {
        //TODO: allow writing past page boundaries
        let virt_data = virt.data();
        let size = mem::size_of::<T>();
        if (virt_data & A::PAGE_ADDRESS_MASK) != ((virt_data + (size - 1)) & A::PAGE_ADDRESS_MASK) {
            panic!(
                "write: 0x{:X} size 0x{:X} passes page boundary",
                virt_data, size
            );
        }

        if let Some((phys, flags)) = self.translate(virt) {
            if flags.has_write() {
                self.write_phys(phys, value);
            } else {
                panic!("write: 0x{:X} size 0x{:X} not writable", virt_data, size);
            }
        } else {
            panic!("write: 0x{:X} size 0x{:X} not present", virt_data, size);
        }
    }

    fn write_bytes(&mut self, virt: VirtualAddress, value: u8, count: usize) {
        //TODO: allow writing past page boundaries
        let virt_data = virt.data();
        if (virt_data & A::PAGE_ADDRESS_MASK) != ((virt_data + (count - 1)) & A::PAGE_ADDRESS_MASK)
        {
            panic!(
                "write_bytes: 0x{:X} count 0x{:X} passes page boundary",
                virt_data, count
            );
        }

        if let Some((phys, flags)) = self.translate(virt) {
            if flags.has_write() {
                self.write_phys_bytes(phys, value, count);
            } else {
                panic!(
                    "write_bytes: 0x{:X} count 0x{:X} not writable",
                    virt_data, count
                );
            }
        } else {
            panic!(
                "write_bytes: 0x{:X} count 0x{:X} not present",
                virt_data, count
            );
        }
    }

    fn invalidate(&mut self, _address: VirtualAddress) {
        unimplemented!("EmulateArch::invalidate not implemented");
    }

    //TODO: cleanup
    fn invalidate_all(&mut self) {
        self.map.clear();

        // PML4
        let a4 = self.table_addr.data();
        for i4 in 0..A::PAGE_ENTRIES {
            let e3 = self.read_phys::<usize>(PhysicalAddress::new(a4 + i4 * A::PAGE_ENTRY_SIZE));
            let f3 = e3 & A::ENTRY_FLAGS_MASK;
            if f3 & A::ENTRY_FLAG_PRESENT == 0 {
                continue;
            }

            // Page directory pointer
            let a3 = ((e3 >> A::ENTRY_ADDRESS_SHIFT) & A::ENTRY_ADDRESS_MASK) << A::PAGE_SHIFT;
            for i3 in 0..A::PAGE_ENTRIES {
                let e2 =
                    self.read_phys::<usize>(PhysicalAddress::new(a3 + i3 * A::PAGE_ENTRY_SIZE));
                let f2 = e2 & A::ENTRY_FLAGS_MASK;
                if f2 & A::ENTRY_FLAG_PRESENT == 0 {
                    continue;
                }

                // Page directory
                let a2 = ((e2 >> A::ENTRY_ADDRESS_SHIFT) & A::ENTRY_ADDRESS_MASK) << A::PAGE_SHIFT;
                for i2 in 0..A::PAGE_ENTRIES {
                    let e1 =
                        self.read_phys::<usize>(PhysicalAddress::new(a2 + i2 * A::PAGE_ENTRY_SIZE));
                    let f1 = e1 & A::ENTRY_FLAGS_MASK;
                    if f1 & A::ENTRY_FLAG_PRESENT == 0 {
                        continue;
                    }

                    // Page table
                    let a1 =
                        ((e1 >> A::ENTRY_ADDRESS_SHIFT) & A::ENTRY_ADDRESS_MASK) << A::PAGE_SHIFT;
                    for i1 in 0..A::PAGE_ENTRIES {
                        let e = self
                            .read_phys::<usize>(PhysicalAddress::new(a1 + i1 * A::PAGE_ENTRY_SIZE));
                        let f = e & A::ENTRY_FLAGS_MASK;
                        if f & A::ENTRY_FLAG_PRESENT == 0 {
                            continue;
                        }

                        // Page
                        let page = (i4 << 39) | (i3 << 30) | (i2 << 21) | (i1 << 12);
                        //println!("map 0x{:X} to 0x{:X}, 0x{:X}", page, a, f);
                        self.map
                            .insert(VirtualAddress::new(page), PageEntry::from_data(e));
                    }
                }
            }
        }
    }

    fn get_table(&self) -> PhysicalAddress {
        self.table_addr
    }

    fn set_table(&mut self, address: PhysicalAddress) {
        self.table_addr = address;
        self.invalidate_all();
    }
}
