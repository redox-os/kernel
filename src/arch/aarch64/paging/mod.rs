//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

pub mod mapper;

/// Initialize MAIR
#[cold]
pub unsafe fn init() {
    unsafe {
        rmm::aarch64::init_mair();
    }
}
