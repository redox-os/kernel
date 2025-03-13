use super::RequestTimings;

#[cfg(feature = "scheduler_eevdf")]
#[derive(Clone, Debug)]
pub struct EevdfData {
    pub timings: RequestTimings,
    pub weight: i64,
    pub lag: usize,
    pub used: u64,
    pub has_joined: bool,
    pub is_running: bool,
    // pub actions: alloc::vec::Vec<alloc::string::String>,
}

#[cfg(feature = "scheduler_eevdf")]
impl Default for EevdfData {
    fn default() -> Self {
        Self {
            timings: RequestTimings::default(),
            weight: 5,
            lag: 0,
            used: 0,
            has_joined: false,
            is_running: false,
            // actions: alloc::vec::Vec::new(),
        }
    }
}
