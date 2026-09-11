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

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        println!("{}:ERROR -- {}", core::module_path!(), format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        println!("{}:WARN -- {}", core::module_path!(), format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        println!("{}:INFO -- {}", core::module_path!(), format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if cfg!(any(target_arch = "aarch64", target_arch = "riscv64")) {
            println!("{}:DEBUG -- {}", core::module_path!(), format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        if false {
            println!("{}:TRACE -- {}", core::module_path!(), format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! impl_pool_type_arc(
    ($name:ident) => {
        mod impl_pool_type_arc {
            use super::*;
            pub static STATE: ::spin::Mutex<$crate::context::pool::State<::alloc::sync::Arc<$name>>> = ::spin::Mutex::new($crate::context::pool::State::new());
        }
        unsafe impl $crate::context::pool::PoolType for ::alloc::sync::Arc<$name> {
            const ITEM_SIZE: usize =
                (::core::mem::size_of::<$name>().next_multiple_of(::core::mem::size_of::<usize>()) + 2 * core::mem::size_of::<usize>()).next_multiple_of(Self::ITEM_ALIGN);
            const ITEM_ALIGN: usize = ::core::mem::align_of::<$name>();

            fn state() -> &'static ::spin::Mutex<$crate::context::pool::State<Self>> {
                const {
                    assert!(Self::ITEM_SIZE <= 4 * $crate::memory::PAGE_SIZE);
                    assert!(Self::ITEM_SIZE >= size_of::<usize>());
                    assert!(Self::ITEM_SIZE % size_of::<usize>() == 0);

                    assert!(Self::ITEM_ALIGN <= 4 * $crate::memory::PAGE_SIZE);
                };

                &impl_pool_type_arc::STATE
            }
            fn name() -> &'static str {
                ::core::any::type_name::<$name>()
            }
        }
    };
);
