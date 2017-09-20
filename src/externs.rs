/// Memcpy
///
/// Copy N bytes of memory from one location to another.
///
/// This faster implementation works by copying bytes not one-by-one, but in
/// groups of 8 bytes (or 4 bytes in the case of 32-bit architectures).
#[cfg(target_pointer_width = "64")]
#[no_mangle]
pub unsafe extern fn memcpy(dest: *mut u8, src: *const u8,
                            n: usize) -> *mut u8 {
    let n_64: usize = n/8; // Number of 64-bit groups
    let mut i: usize = 0;

    // Copy 8 bytes at a time
    while i < n_64 {
        *((dest as usize + i) as *mut u64) =
            *((src as usize + i) as *const u64);
        i += 8;
    }

    // Copy 1 byte at a time
    while i < n {
        *((dest as usize + i) as *mut u8) = *((src as usize + i) as *const u8);
        i += 1;
    }

    dest
}

// 32-bit version of the function above
#[cfg(target_pointer_width = "32")]
#[no_mangle]
pub unsafe extern fn memcpy(dest: *mut u8, src: *const u8,
                            n: usize) -> *mut u8 {
    let n_32: usize = n/4; // Number of 32-bit groups
    let mut i: usize = 0;

    // Copy 4 bytes at a time
    while i < n_32 {
        *((dest as usize + i) as *mut u32) =
            *((src as usize + i) as *const u32);
        i += 4;
    }

    // Copy 1 byte at a time
    while i < n {
        *((dest as usize + i) as *mut u8) = *((src as usize + i) as *const u8);
        i += 1;
    }

    dest
}

/// Memmove
///
/// Copy N bytes of memory from src to dest. The memory areas may overlap.
///
/// This faster implementation works by copying bytes not one-by-one, but in
/// groups of 8 bytes (or 4 bytes in the case of 32-bit architectures).
#[cfg(target_pointer_width = "64")]
#[no_mangle]
pub unsafe extern fn memmove(dest: *mut u8, src: *const u8,
                             n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        let n_64: usize = n/8; // Number of 64-bit groups
        let mut i: usize = n_64*8;

        // Copy 8 bytes at a time
        while i != 0 {
            i -= 8;
            *((dest as usize + i) as *mut u64) =
                *((src as usize + i) as *const u64);
        }

        let mut i: usize = n;

        // Copy 1 byte at a time
        while i != n_64*8 {
            i -= 1;
            *((dest as usize + i) as *mut u8) =
                *((src as usize + i) as *const u8);
        }
    } else {
        let n_64: usize = n/8; // Number of 64-bit groups
        let mut i: usize = 0;

        // Copy 8 bytes at a time
        while i < n_64 {
            *((dest as usize + i) as *mut u64) =
                *((src as usize + i) as *const u64);
            i += 8;
        }

        // Copy 1 byte at a time
        while i < n {
            *((dest as usize + i) as *mut u8) =
                *((src as usize + i) as *const u8);
            i += 1;
        }
    }

    dest
}

// 32-bit version of the function above
#[cfg(target_pointer_width = "32")]
#[no_mangle]
pub unsafe extern fn memmove(dest: *mut u8, src: *const u8,
                             n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        let n_32: usize = n/4; // Number of 32-bit groups
        let mut i: usize = n_32*4;

        // Copy 4 bytes at a time
        while i != 0 {
            i -= 4;
            *((dest as usize + i) as *mut u32) =
                *((src as usize + i) as *const u32);
        }

        let mut i: usize = n;

        // Copy 1 byte at a time
        while i != n_32*4 {
            i -= 1;
            *((dest as usize + i) as *mut u8) =
                *((src as usize + i) as *const u8);
        }
    } else {
        let n_32: usize = n/4; // Number of 32-bit groups
        let mut i: usize = 0;

        // Copy 4 bytes at a time
        while i < n_32 {
            *((dest as usize + i) as *mut u32) =
                *((src as usize + i) as *const u32);
            i += 4;
        }

        // Copy 1 byte at a time
        while i < n {
            *((dest as usize + i) as *mut u8) =
                *((src as usize + i) as *const u8);
            i += 1;
        }
    }

    dest
}

/// Memset
///
/// Fill a block of memory with a specified value.
///
/// This faster implementation works by setting bytes not one-by-one, but in
/// groups of 8 bytes (or 4 bytes in the case of 32-bit architectures).
#[cfg(target_pointer_width = "64")]
#[no_mangle]
pub unsafe extern fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u64;
    let c = (c << 56) | (c << 48) | (c << 40) | (c << 32)
          | (c << 24) | (c << 16) | (c << 8)  | c;
    let n_64: usize = n/8;
    let mut i: usize = 0;

    // Set 8 bytes at a time
    while i < n_64 {
        *((dest as usize + i) as *mut u64) = c;
        i += 8;
    }

    let c = c as u8;

    // Set 1 byte at a time
    while i < n {
        *((dest as usize + i) as *mut u8) = c;
        i += 1;
    }

    dest
}

// 32-bit version of the function above
#[cfg(target_pointer_width = "32")]
#[no_mangle]
pub unsafe extern fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u32;
    let c = (c << 24) | (c << 16) | (c << 8)  | c;
    let n_32: usize = n/4;
    let mut i: usize = 0;

    // Set 4 bytes at a time
    while i < n_32 {
        *((dest as usize + i) as *mut u32) = c;
        i += 4;
    }

    let c = c as u8;

    // Set 1 byte at a time
    while i < n {
        *((dest as usize + i) as *mut u8) = c;
        i += 1;
    }

    dest
}

/// Memcmp
///
/// Compare two blocks of memory.
///
/// This faster implementation works by comparing bytes not one-by-one, but in
/// groups of 8 bytes (or 4 bytes in the case of 32-bit architectures).
#[cfg(target_pointer_width = "64")]
#[no_mangle]
pub unsafe extern fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let n_64: usize = n/8;
    let mut i: usize = 0;

    while i < n_64 {
        let a = *((s1 as usize + i) as *const u64);
        let b = *((s2 as usize + i) as *const u64);
        if a != b {
            let n: usize = i + 8;
            // Find the one byte that is not equal
            while i < n {
                let a = *((s1 as usize + i) as *const u8);
                let b = *((s2 as usize + i) as *const u8);
                if a != b {
                    return a as i32 - b as i32;
                }
                i += 1;
            }
        }
        i += 8;
    }

    while i < n {
        let a = *((s1 as usize + i) as *const u8);
        let b = *((s2 as usize + i) as *const u8);
        if a != b {
            return a as i32 - b as i32;
        }
        i += 1;
    }

    0
}

#[cfg(target_pointer_width = "32")]
#[no_mangle]
pub unsafe extern fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let n_32: usize = n/4;
    let mut i: usize = 0;

    while i < n_32 {
        let a = *((s1 as usize + i) as *const u32);
        let b = *((s2 as usize + i) as *const u32);
        if a != b {
            let n: usize = i + 4;
            // Find the one byte that is not equal
            while i < n {
                let a = *((s1 as usize + i) as *const u8);
                let b = *((s2 as usize + i) as *const u8);
                if a != b {
                    return a as i32 - b as i32;
                }
                i += 1;
            }
        }
        i += 4;
    }

    while i < n {
        let a = *((s1 as usize + i) as *const u8);
        let b = *((s2 as usize + i) as *const u8);
        if a != b {
            return a as i32 - b as i32;
        }
        i += 1;
    }

    0
}
