use core::{mem, slice, str};

use crate::paging::{ActivePageTable, Page, VirtualAddress};
use crate::syscall::error::*;

fn validate(address: usize, size: usize, writable: bool) -> Result<()> {
    let end_offset = size.checked_sub(1).ok_or(Error::new(EFAULT))?;
    let end_address = address.checked_add(end_offset).ok_or(Error::new(EFAULT))?;

    let active_table = unsafe { ActivePageTable::new() };

    let start_page = Page::containing_address(VirtualAddress::new(address));
    let end_page = Page::containing_address(VirtualAddress::new(end_address));
    for page in Page::range_inclusive(start_page, end_page) {
        if let Some(page_flags) = active_table.translate_page_flags(page) {
            if ! page_flags.has_user() {
                // println!("{:X}: Not usermode", page.start_address().data());
                return Err(Error::new(EFAULT));
            }

            if writable && ! page_flags.has_write() {
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

/// Convert a pointer and length to slice, if valid
//TODO: Mark unsafe
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
