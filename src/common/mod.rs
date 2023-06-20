use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::memory::Enomem;

pub mod aligned_box;
#[macro_use]
pub mod int_like;
pub mod unique;

/// Debug macro, lifted from the std
#[macro_export]
macro_rules! dbg {
    () => {
        $crate::println!("[{}:{}]", file!(), line!());
    };
    ($val:expr) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                $crate::println!("[{}:{}] {} = {:#?}",
                    file!(), line!(), stringify!($val), &tmp);
                tmp
            }
        }
    };
    // Trailing comma with single argument is ignored
    ($val:expr,) => { $crate::dbg!($val) };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}

pub fn try_new_vec_with_exact_size<T>(len: usize) -> Result<Vec<T>, Enomem> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(len).map_err(|_| Enomem)?;
    Ok(vec.into())
}
pub fn try_box_slice_new<T: Clone>(value: T, len: usize) -> Result<Box<[T]>, Enomem> {
    let mut vec = try_new_vec_with_exact_size(len)?;
    vec.resize(len, value);
    Ok(vec.into())
}
