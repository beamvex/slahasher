#![deny(missing_docs)]
//! Hashing functions and hash value types.
//!
//! This crate provides implementations of a small set of cryptographic hash algorithms and a
//! common [`Hash`] type for working with computed digests.
/// Core hash value type and traits.
pub mod hash;

/// Supported hash algorithms.
pub mod hash_algorithm;

/// Hasher trait.
pub mod hasher;

/// Keccak-256 hash implementation.
pub mod keccak256;

/// Keccak-384 hash implementation.
pub mod keccak384;

/// Keccak-512 hash implementation.
pub mod keccak512;

/// RIPEMD-160 hash implementation.
pub mod ripemd160;

/// SHA-256 hash implementation.
pub mod sha256;

pub use hash::Hash;
pub use hash_algorithm::HashAlgorithm;
pub use hasher::Hasher;
pub use keccak256::Keccak256;
pub use keccak384::Keccak384;
pub use keccak512::Keccak512;
pub use ripemd160::Ripemd160;
pub use sha256::Sha256;
