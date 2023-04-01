use core::mem;

const WORD_SIZE: usize = mem::size_of::<usize>();

/// Memcpy
///
/// Copy N bytes of memory from one location to another.
///
/// This faster implementation works by copying bytes not one-by-one, but in
/// groups of 8 bytes (or 4 bytes in the case of 32-bit architectures).
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    // TODO: Alignment? Some sources claim that even on relatively modern µ-arches, unaligned
    // accesses spanning two pages, can take dozens of cycles. That means chunk-based memcpy can
    // even be slower for small lengths if alignment is not taken into account.
    //
    // TODO: Optimize out smaller loops by first checking if len < WORD_SIZE, and possibly if
    // dest + WORD_SIZE spans two pages, then doing one unaligned copy, then aligning up, and then
    // doing one last unaligned copy?
    //
    // TODO: While we use the -fno-builtin equivalent, can we guarantee LLVM won't insert memcpy
    // call inside here? Maybe write it in assembly?

    let mut i = 0_usize;

    // First we copy len / WORD_SIZE chunks...

    let chunks = len / WORD_SIZE;

    while i < chunks * WORD_SIZE {
        dest.add(i)
            .cast::<usize>()
            .write_unaligned(src.add(i).cast::<usize>().read_unaligned());
        i += WORD_SIZE;
    }

    // .. then we copy len % WORD_SIZE bytes
    while i < len {
        dest.add(i).write(src.add(i).read());
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
#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    let chunks = len / WORD_SIZE;

    // TODO: also require dest - src < len before choosing to copy backwards?
    if src < dest as *const u8 {
        // We have to copy backwards if copying upwards.

        let mut i = len;

        while i != chunks * WORD_SIZE {
            i -= 1;
            dest.add(i).write(src.add(i).read());
        }

        while i > 0 {
            i -= WORD_SIZE;

            dest.add(i)
                .cast::<usize>()
                .write_unaligned(src.add(i).cast::<usize>().read_unaligned());
        }
    } else {
        // We have to copy forward if copying downwards.

        let mut i = 0_usize;

        while i < chunks * WORD_SIZE {
            dest.add(i)
                .cast::<usize>()
                .write_unaligned(src.add(i).cast::<usize>().read_unaligned());

            i += WORD_SIZE;
        }

        while i < len {
            dest.add(i).write(src.add(i).read());
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
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, byte: i32, len: usize) -> *mut u8 {
    let byte = byte as u8;

    let mut i = 0;

    let broadcasted = usize::from_ne_bytes([byte; WORD_SIZE]);
    let chunks = len / WORD_SIZE;

    while i < chunks * WORD_SIZE {
        dest.add(i).cast::<usize>().write_unaligned(broadcasted);
        i += WORD_SIZE;
    }

    while i < len {
        dest.add(i).write(byte);
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
#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, len: usize) -> i32 {
    let mut i = 0_usize;

    // First compare WORD_SIZE chunks...
    let chunks = len / WORD_SIZE;

    while i < chunks * WORD_SIZE {
        let a = s1.add(i).cast::<usize>().read_unaligned();
        let b = s2.add(i).cast::<usize>().read_unaligned();

        if a != b {
            // x86 has had bswap since the 80486, and the compiler will likely use the faster
            // movbe. AArch64 has the REV instruction, which I think is universally available.
            let diff = usize::from_be(a).wrapping_sub(usize::from_be(b)) as isize;

            // TODO: If chunk size == 32 bits, diff can be returned directly.
            return diff.signum() as i32;
        }
        i += WORD_SIZE;
    }

    // ... and then compare bytes.
    while i < len {
        let a = s1.add(i).read();
        let b = s2.add(i).read();

        if a != b {
            return i32::from(a) - i32::from(b);
        }
        i += 1;
    }

    0
}
