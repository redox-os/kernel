/// Print to console
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::arch::debug::Writer::new(), $($arg)*);
    });
}

/// Print with new line to console
#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($fmt:expr_2021) => (print!(concat!($fmt, "\n")));
    ($fmt:expr_2021, $($arg:tt)*) => (print!(concat!($fmt, "\n"), $($arg)*));
}
