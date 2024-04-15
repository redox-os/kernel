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

pub fn itoa(mut x: u64, buf: &mut [u8; 32], radix: u32) -> &str {
    let mut i = 32;
    while x != 0 {
        i -= 1;
        let d = (x % radix as u64) as u8;
        if d < 10 {
            buf[i] = b'0' + d;
        } else {
            buf[i] = b'a' + (d - 10);
        }
        x /= radix as u64;
    }
    core::str::from_utf8(&buf[i..]).unwrap()
}
