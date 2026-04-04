use alloc::boxed::Box;
use rmm::PhysicalAddress;

pub trait Rxsdt {
    fn iter(&self) -> Box<dyn Iterator<Item = PhysicalAddress>>;
}
