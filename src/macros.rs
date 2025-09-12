/// Print to console
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::log::Writer::new(), $($arg)*);
    });
}

/// Print with new line to console
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = writeln!($crate::log::Writer::new(), $($arg)*);
    });
}
