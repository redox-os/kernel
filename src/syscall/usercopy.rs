use syscall::dirent::Buffer;

use crate::{
    memory::PAGE_SIZE,
    paging::{Page, VirtualAddress},
};

use crate::arch::{arch_copy_from_user, arch_copy_to_user};

use crate::syscall::error::{Error, Result, EFAULT, EINVAL};

#[derive(Clone, Copy)]
pub struct UserSlice<const READ: bool, const WRITE: bool> {
    base: usize,
    len: usize,
}
pub type UserSliceRo = UserSlice<true, false>;
pub type UserSliceWo = UserSlice<false, true>;

impl<const READ: bool, const WRITE: bool> UserSlice<READ, WRITE> {
    pub fn empty() -> Self {
        Self { base: 0, len: 0 }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn addr(&self) -> usize {
        self.base
    }
    pub fn new(base: usize, len: usize) -> Result<Self> {
        if base >= crate::USER_END_OFFSET || base.saturating_add(len) >= crate::USER_END_OFFSET {
            return Err(Error::new(EFAULT));
        }

        Ok(Self { base, len })
    }
    /// Split [0, end) into [0, idx) and [idx, end)
    pub fn split_at(self, idx: usize) -> Option<(Self, Self)> {
        if idx > self.len {
            return None;
        }
        Some((
            Self {
                base: self.base,
                len: idx,
            },
            Self {
                base: self.base + idx,
                len: self.len - idx,
            },
        ))
    }
    pub fn advance(self, by: usize) -> Option<Self> {
        Some(self.split_at(by)?.1)
    }
    pub fn limit(self, to: usize) -> Option<Self> {
        Some(self.split_at(to)?.0)
    }
    pub fn none_if_null(self) -> Option<Self> {
        if self.addr() == 0 {
            None
        } else {
            Some(self)
        }
    }
    /// Not unsafe, because user memory is not covered by the memory model that decides if
    /// something is UB, but it can break logic invariants
    pub fn reinterpret_unchecked<const NEW_READ: bool, const NEW_WRITE: bool>(
        self,
    ) -> UserSlice<NEW_READ, NEW_WRITE> {
        UserSlice {
            base: self.base,
            len: self.len,
        }
    }
    pub fn in_variable_chunks(self, chunk_size: usize) -> impl Iterator<Item = Self> {
        (0..self.len()).step_by(chunk_size).map(move |i| {
            self.advance(i)
                .expect("already limited by length, must succeed")
        })
    }
    pub fn in_exact_chunks(self, chunk_size: usize) -> impl Iterator<Item = Self> {
        (0..self.len().div_floor(chunk_size)).map(move |i| {
            self.advance(i * chunk_size)
                .expect("already limited by length, must succeed")
                .limit(chunk_size)
                .expect("length is aligned")
        })
    }
}
impl<const WRITE: bool> UserSlice<true, WRITE> {
    pub fn copy_to_slice(self, slice: &mut [u8]) -> Result<()> {
        debug_assert!(is_kernel_mem(slice));

        if self.len != slice.len() {
            return Err(Error::new(EINVAL));
        }

        if unsafe { arch_copy_from_user(slice.as_mut_ptr() as usize, self.base, self.len) } == 0 {
            Ok(())
        } else {
            Err(Error::new(EFAULT))
        }
    }
    pub unsafe fn read_exact<T>(self) -> Result<T> {
        let mut t: T = core::mem::zeroed();
        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                (&mut t as *mut T).cast::<u8>(),
                core::mem::size_of::<T>(),
            )
        };

        self.limit(core::mem::size_of::<T>())
            .ok_or(Error::new(EINVAL))?
            .copy_to_slice(slice)?;

        Ok(t)
    }
    pub fn copy_common_bytes_to_slice(self, slice: &mut [u8]) -> Result<usize> {
        let min = core::cmp::min(self.len(), slice.len());
        self.limit(min)
            .expect("min(len, x) is always <= len")
            .copy_to_slice(&mut slice[..min])?;
        Ok(min)
    }
    // TODO: Merge int IO functions?
    pub fn read_usize(self) -> Result<usize> {
        let mut ret = 0_usize.to_ne_bytes();
        self.limit(core::mem::size_of::<usize>())
            .ok_or(Error::new(EINVAL))?
            .copy_to_slice(&mut ret)?;
        Ok(usize::from_ne_bytes(ret))
    }
    pub fn read_u32(self) -> Result<u32> {
        let mut ret = 0_u32.to_ne_bytes();
        self.limit(4)
            .ok_or(Error::new(EINVAL))?
            .copy_to_slice(&mut ret)?;
        Ok(u32::from_ne_bytes(ret))
    }
    pub fn read_u64(self) -> Result<u64> {
        let mut ret = 0_u64.to_ne_bytes();
        self.limit(8)
            .ok_or(Error::new(EINVAL))?
            .copy_to_slice(&mut ret)?;
        Ok(u64::from_ne_bytes(ret))
    }
    pub fn usizes(self) -> impl Iterator<Item = Result<usize>> {
        self.in_exact_chunks(core::mem::size_of::<usize>())
            .map(Self::read_usize)
    }
}
impl<const READ: bool> UserSlice<READ, true> {
    pub fn copy_from_slice(self, slice: &[u8]) -> Result<()> {
        // A zero sized slice will like have 0x1 as address
        debug_assert!(is_kernel_mem(slice) || slice.len() == 0);

        if self.len != slice.len() {
            return Err(Error::new(EINVAL));
        }

        if unsafe { arch_copy_to_user(self.base, slice.as_ptr() as usize, self.len) } == 0 {
            Ok(())
        } else {
            Err(Error::new(EFAULT))
        }
    }
    pub fn copy_common_bytes_from_slice(self, slice: &[u8]) -> Result<usize> {
        let min = core::cmp::min(self.len(), slice.len());
        self.limit(min)
            .expect("min(len, x) is always <= len")
            .copy_from_slice(&slice[..min])?;
        Ok(min)
    }
    pub fn copy_exactly(self, slice: &[u8]) -> Result<()> {
        self.limit(slice.len())
            .ok_or(Error::new(EINVAL))?
            .copy_from_slice(slice)?;
        Ok(())
    }
    pub fn write_usize(self, word: usize) -> Result<()> {
        self.limit(core::mem::size_of::<usize>())
            .ok_or(Error::new(EINVAL))?
            .copy_from_slice(&word.to_ne_bytes())?;
        Ok(())
    }
    pub fn write_u32(self, int: u32) -> Result<()> {
        self.limit(core::mem::size_of::<u32>())
            .ok_or(Error::new(EINVAL))?
            .copy_from_slice(&int.to_ne_bytes())?;
        Ok(())
    }
}

impl UserSliceRo {
    pub fn ro(base: usize, size: usize) -> Result<Self> {
        Self::new(base, size)
    }
}
impl UserSliceWo {
    pub fn wo(base: usize, size: usize) -> Result<Self> {
        Self::new(base, size)
    }
}

fn is_kernel_mem(slice: &[u8]) -> bool {
    (slice.as_ptr() as usize) >= crate::USER_END_OFFSET
        && (slice.as_ptr() as usize).checked_add(slice.len()).is_some()
}

/// Convert `[addr, addr+size)` into `(page, page_count)`.
///
/// This will fail if:
///
/// - the base address is not page-aligned,
/// - the length is not page-aligned,
/// - the region is empty (EINVAL), or
/// - any byte in the region exceeds USER_END_OFFSET (EFAULT).
// TODO: Return PageSpan
pub fn validate_region(address: usize, size: usize) -> Result<(Page, usize)> {
    if address % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 || size == 0 {
        return Err(Error::new(EINVAL));
    }
    if address.saturating_add(size) > crate::USER_END_OFFSET {
        return Err(Error::new(EFAULT));
    }
    Ok((
        Page::containing_address(VirtualAddress::new(address)),
        size / PAGE_SIZE,
    ))
}
impl Buffer<'static> for UserSliceWo {
    fn empty() -> Self {
        UserSliceWo::empty()
    }
    fn length(&self) -> usize {
        self.len()
    }
    fn split_at(self, index: usize) -> Option<[Self; 2]> {
        let (a, b) = self.split_at(index)?;
        Some([a, b])
    }
    fn copy_from_slice_exact(self, src: &[u8]) -> Result<()> {
        self.copy_exactly(src)
    }
    fn zero_out(self) -> Result<()> {
        // TODO: Implement this. Don't need to as long as the header size is constant, for now.
        Ok(())
    }
}
