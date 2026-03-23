use crate::Hasher;
use crate::{Hash, HashAlgorithm};
use base_xx::ByteVec;
use base_xx::SerialiseError;
use sha3::{Digest, Keccak384 as Keccak384Impl};
use std::sync::Arc;

/// Keccak-384 hash implementation.
pub struct Keccak384 {}

impl Keccak384 {
    /// Creates a `Keccak384` hash from the provided bytes.
    ///
    /// # Errors
    ///
    /// Returns `SerialiseError` if the computed hash is not 48 bytes.
    #[must_use = "the computed hash is returned in the Ok value"]
    pub fn try_from_bytes(bytes: &ByteVec) -> Result<Hash, SerialiseError> {
        let mut hasher = Keccak384Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let result = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 48 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }
        Ok(Hash::new(
            HashAlgorithm::KECCAK384,
            ByteVec::new(Arc::new(bytes)),
        ))
    }
}

impl Hasher for Keccak384 {
    fn try_hash(byte_vec: &ByteVec) -> Result<Hash, SerialiseError> {
        Self::try_from_bytes(byte_vec)
    }
}

#[cfg(test)]
mod tests {

    use slogger::debug;

    use base_xx::{ByteVec, Encoding};

    use super::*;

    #[test]
    pub fn test_keccak384() {
        let test = ByteVec::new(Arc::new(b"this is a really good test".to_vec()));

        match Hash::try_hash(&test, HashAlgorithm::KECCAK384) {
            Ok(hash) => match hash.try_to_byte_vec() {
                Ok(bytes) => match bytes.try_encode(Encoding::Base36) {
                    Ok(serialised) => {
                        let serialised = serialised.get_string();
                        debug!("sha256 {serialised}");
                        assert_eq!(
                            serialised,
                            "7mao3tmazqcmoyumzrkh7oixj5yumrp0u1sg14qw9m1uo2lvwo97ueowvr9mqpdm68a3e2bztph1"
                        );
                    }
                    Err(error) => debug!("serialisation error: {error:?}"),
                },
                Err(error) => debug!("serialisation error: {error:?}"),
            },
            Err(error) => debug!("hash error: {error:?}"),
        }
    }
}
