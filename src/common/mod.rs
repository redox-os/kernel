pub mod aligned_box;
#[macro_use]
pub mod int_like;

/// Debug macro, lifted from the std
#[macro_export]
macro_rules! dbg {
    () => {
        $crate::println!("[{}:{}]", file!(), line!());
    };
    ($val:expr_2021) => {
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
    ($val:expr_2021,) => { $crate::dbg!($val) };
    ($($val:expr_2021),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
