// TODO: Maybe stop handing out slices and instead use a wrapper type that supports copying etc.
// Invalid pages will cause page faults, which can be handled so that they are caught and EFAULT is
// returned. This will also make SMAP much, much, easier. c.f. Linux's copy_from_user, copy_to_user
// which are written in assembly and handle page faults.
use core::{mem, slice, str};

use crate::context;
use crate::memory::PAGE_SIZE;
use crate::paging::{Page, TableKind, VirtualAddress};
use crate::syscall::error::*;

use alloc::sync::Arc;

fn validate(address: usize, size: usize, writable: bool) -> Result<()> {
    if VirtualAddress::new(address.saturating_add(size)).kind() != TableKind::User {
        return Err(Error::new(EFAULT));
    }

    let end_offset = size.checked_sub(1).ok_or(Error::new(EFAULT))?;
    let end_address = address.checked_add(end_offset).ok_or(Error::new(EFAULT))?;

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
    let addr_space = addr_space.read();

    let start_page = Page::containing_address(VirtualAddress::new(address));
    let end_page = Page::containing_address(VirtualAddress::new(end_address));
    for page in Page::range_inclusive(start_page, end_page) {
        if let Some((_, flags)) = addr_space.table.utable.translate(page.start_address()) {
            if !flags.has_user() {
                // println!("{:X}: Not usermode", page.start_address().data());
                return Err(Error::new(EFAULT));
            }

            if writable && !flags.has_write() {
                // println!("{:X}: Not writable {}", page.start_address().data(), writable);
                return Err(Error::new(EFAULT));
            }
        } else {
            // println!("{:X}: Not found", page.start_address().data());
            return Err(Error::new(EFAULT));
        }
    }

    Ok(())
}

/// Convert a pointer and length to reference, if valid
pub unsafe fn validate_ref<T>(ptr: *const T, size: usize) -> Result<&'static T> {
    if size == mem::size_of::<T>() {
        validate(ptr as usize, mem::size_of::<T>(), false)?;
        Ok(&*ptr)
    } else {
        Err(Error::new(EINVAL))
    }
}

/// Convert a pointer and length to mutable reference, if valid
pub unsafe fn validate_ref_mut<T>(ptr: *mut T, size: usize) -> Result<&'static mut T> {
    if size == mem::size_of::<T>() {
        validate(ptr as usize, mem::size_of::<T>(), false)?;
        Ok(&mut *ptr)
    } else {
        Err(Error::new(EINVAL))
    }
}

/// Convert a pointer and length to slice, if valid
//TODO: Mark unsafe
pub fn validate_slice<T>(ptr: *const T, len: usize) -> Result<&'static [T]> {
    if len == 0 {
        Ok(&[])
    } else {
        validate(ptr as usize, len * mem::size_of::<T>(), false)?;
        Ok(unsafe { slice::from_raw_parts(ptr, len) })
    }
}
/// Convert a pointer with fixed static length to a reference to an array, if valid.
// TODO: This is probably also quite unsafe, mainly because we have no idea unless we do very
// careful checking, that this upholds the rules that LLVM relies with shared references, namely
// that the value cannot change by others. Atomic volatile.
pub unsafe fn validate_array<'a, T, const N: usize>(ptr: *const T) -> Result<&'a [T; N]> {
    validate(ptr as usize, mem::size_of::<T>() * N, false)?;
    Ok(&*ptr.cast::<[T; N]>())
}
pub unsafe fn validate_array_mut<'a, T, const N: usize>(ptr: *mut T) -> Result<&'a mut [T; N]> {
    validate(ptr as usize, mem::size_of::<T>() * N, true)?;
    Ok(&mut *ptr.cast::<[T; N]>())
}

/// Convert a pointer and length to slice, if valid
// TODO: Mark unsafe
//
// FIXME: This is probably never ever safe, except under very special circumstances. Any &mut
// reference will allow LLVM to assume that nobody else will ever modify this value, which is
// certainly not the case for multithreaded userspace programs. Instead, we will want something
// like atomic volatile.
pub fn validate_slice_mut<T>(ptr: *mut T, len: usize) -> Result<&'static mut [T]> {
    if len == 0 {
        Ok(&mut [])
    } else {
        validate(ptr as usize, len * mem::size_of::<T>(), true)?;
        Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
    }
}

/// Convert a pointer and length to str, if valid
//TODO: Mark unsafe
pub fn validate_str(ptr: *const u8, len: usize) -> Result<&'static str> {
    let slice = validate_slice(ptr, len)?;
    str::from_utf8(slice).map_err(|_| Error::new(EINVAL))
}

pub fn validate_region(address: usize, size: usize) -> Result<(Page, usize)> {
    if address % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 || size == 0 {
        return Err(Error::new(EINVAL));
    }
    if address.saturating_add(size) > crate::USER_END_OFFSET {
        return Err(Error::new(EFAULT));
    }
    Ok((Page::containing_address(VirtualAddress::new(address)), size / PAGE_SIZE))
}
