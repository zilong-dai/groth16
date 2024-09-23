/// keccak256 gadget
pub mod keccak256;

/// em_field gadget
pub mod em_field;

pub use keccak256::{keccak256, keccak256_bytes, Keccak256Gadget};

pub use em_field::{nonnative_field_var::EmulatedFpVar, allocated_nonnative_field_var::AllocatedEmulatedFpVar};
