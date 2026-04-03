//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

pub mod mapper;

/// Initialize PAT
#[cold]
pub unsafe fn init() {
    unsafe {
        #[cfg(target_arch = "x86")]
        rmm::x86::init_pat();
        #[cfg(target_arch = "x86_64")]
        rmm::x86_64::init_pat();
    }
}
