//! Collectors. Real implementations land in M1.

/// A collector produces samples on each tick.
pub trait Collector {
    fn name(&self) -> &'static str;
}
