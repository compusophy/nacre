//! unified step + allocation fuel conservation and fractal budget slicing.

use crate::diag::{Diag, DiagCode};

/// deterministic fuel meter shared across reduction steps and arena allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fuel {
    limit: u64,
    used: u64,
}

impl Fuel {
    pub const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub const fn limit(&self) -> u64 {
        self.limit
    }

    pub const fn used(&self) -> u64 {
        self.used
    }

    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// attempt to spend `amount` fuel; returns false if exhausted (leaves `used == limit`).
    pub fn charge(&mut self, amount: u64) -> bool {
        let next = self.used.saturating_add(amount);
        if next > self.limit {
            self.used = self.limit;
            false
        } else {
            self.used = next;
            true
        }
    }

    /// slice a bounded sub-budget for a fractal child cell.
    /// a child can never mint more fuel than the parent currently holds.
    pub fn slice_child(&self, requested: i64) -> Result<Fuel, Diag> {
        if requested < 0 {
            return Err(Diag::runtime(
                DiagCode::InvalidFuelRequest,
                "child fuel budget cannot be negative",
            ));
        }
        let capped = (requested as u64).min(self.remaining());
        Ok(Fuel::new(capped))
    }

    /// settle fuel consumed by a child cell back into the parent's ledger.
    pub fn settle_child(&mut self, child_used: u64) {
        self.used = self.used.saturating_add(child_used).min(self.limit);
    }
}
