use crate::Hasher;
use crate::{Hash, HashAlgorithm};
use base_xx::ByteVec;
use base_xx::SerialiseError;
use sha3::{Digest, Keccak256 as Keccak256Impl};

/// Keccak-256 hash implementation.
pub struct Keccak256 {}

impl Keccak256 {
    /// Creates a `Keccak256` hash from the provided bytes.
    ///
    /// # Errors
    ///
    /// Returns `SerialiseError` if the computed hash is not 32 bytes.
    #[must_use = "the computed hash is returned in the Ok value"]
    pub fn try_from_bytes(bytes: &ByteVec) -> Result<Hash, SerialiseError> {
        let mut hasher = Keccak256Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let result = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 32 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }
        Ok(Hash::new(HashAlgorithm::KECCAK256, ByteVec::new(bytes)))
    }
}

impl Hasher for Keccak256 {
    fn try_hash(byte_vec: &ByteVec) -> Result<Hash, SerialiseError> {
        Self::try_from_bytes(byte_vec)
    }
}

#[cfg(test)]
mod tests {

    use slogger::debug;

    use base_xx::byte_vec::Encodable;
    use base_xx::{ByteVec, Encoding};

    use super::*;

    #[test]
    pub fn test_keccak256() {
        let test = ByteVec::new(b"this is a really good test".to_vec());

        match Hash::try_hash(&test, HashAlgorithm::KECCAK256) {
            Ok(hash) => match Hash::try_encode(&hash, Encoding::Base36) {
                Ok(serialised) => {
                    let serialised = serialised.get_string();
                    debug!("sha256 {serialised}");
                    assert_eq!(
                        serialised,
                        "htrjv54adtzf7cxhi9mjeermo1dlve4g4r5tjdy61fjho90rskf"
                    );
                }
                Err(error) => debug!("serialisation error: {error:?}"),
            },
            Err(error) => debug!("hash error: {error:?}"),
        }
    }
}
