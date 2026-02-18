use crate::{Hash, HashAlgorithm};
use base_xx::ByteVec;
use base_xx::SerialiseError;
use sha2::{Digest, Sha256 as Sha256Impl};

/// SHA-256 hash implementation.
///
/// This type provides methods to create and manipulate SHA-256 hashes.
/// SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte)
/// hash value.
#[derive(Debug)]
pub struct Sha256 {
    /// The raw bytes of the hash value
    hash: Hash,
}

impl Sha256 {
    /// Creates a new SHA-256 hash value.
    ///
    /// # Arguments
    /// * `hash` - The raw hash value
    #[must_use = "This creates a new hash value but does nothing if unused"]
    pub const fn new(hash: Hash) -> Self {
        Self { hash }
    }

    #[must_use]
    pub fn get_hash(self) -> Hash {
        self.hash
    }

    /// Creates a SHA-256 hash from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - The data to hash
    ///
    /// # Returns
    /// A new SHA-256 hash value containing the hash of the input data
    #[must_use = "This computes a hash value but does nothing if unused"]
    fn try_from_bytes(bytes: &ByteVec) -> Result<Self, SerialiseError> {
        let mut hasher = Sha256Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let result = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 32 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }

        let hash = Hash::new(HashAlgorithm::SHA256, bytes);
        Ok(Self::new(hash))
    }
}

impl TryFrom<&ByteVec> for Sha256 {
    type Error = SerialiseError;
    fn try_from(value: &ByteVec) -> Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

#[cfg(test)]
mod tests {

    use slogger::debug;

    use base_xx::byte_vec::Encodable;
    use base_xx::{ByteVec, Encoding};

    use super::*;

    #[test]
    pub fn test_sha256() {
        let test = ByteVec::new(b"this is a really good test".to_vec());

        match Hash::try_hash(&test, HashAlgorithm::SHA256) {
            Ok(hash) => match Hash::try_encode(&hash, Encoding::Base36) {
                Ok(serialised) => debug!("sha256 {serialised}"),
                Err(error) => debug!("serialisation error: {error:?}"),
            },
            Err(error) => debug!("hash error: {error:?}"),
        }
    }
}
