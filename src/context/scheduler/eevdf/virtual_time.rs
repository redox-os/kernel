use core::{
    cmp::Ordering,
    ops::{Add, AddAssign, Sub, SubAssign},
};

#[derive(Copy, Clone, Debug, Default)]
pub struct VirtualTime(f64);

impl VirtualTime {
    pub const fn new(val: f64) -> Self {
        Self(val)
    }
}

impl AddAssign for VirtualTime {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl SubAssign for VirtualTime {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0
    }
}

impl Add for VirtualTime {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut copy = self;
        copy += rhs;
        copy
    }
}

impl Sub for VirtualTime {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut copy = self;
        copy -= rhs;
        copy
    }
}

impl PartialEq for VirtualTime {
    fn eq(&self, other: &Self) -> bool {
        self.0.total_cmp(&other.0) == Ordering::Equal
    }
}

impl Eq for VirtualTime {}

impl Ord for VirtualTime {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for VirtualTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Display for VirtualTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
