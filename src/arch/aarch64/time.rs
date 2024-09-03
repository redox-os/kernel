pub fn monotonic_absolute() -> u128 {
    //TODO: aarch64 generic timer counter
    *crate::time::OFFSET.lock()
}
