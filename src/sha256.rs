use crate::Hasher;
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
pub struct Sha256 {}

impl Sha256 {
    /// Creates a SHA-256 hash from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - The data to hash
    ///
    /// # Errors
    ///
    /// Returns `SerialiseError` if the computed hash is not 32 bytes.
    /// # Returns
    /// A new SHA-256 hash value containing the hash of the input data
    #[must_use = "This computes a hash value but does nothing if unused"]
    fn try_from_bytes(bytes: &ByteVec) -> Result<Hash, SerialiseError> {
        let mut hasher = Sha256Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let result = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 32 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }

        let hash = Hash::new(HashAlgorithm::SHA256, bytes);
        Ok(hash)
    }
}

impl Hasher for Sha256 {
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
    pub fn test_sha256() {
        let test = ByteVec::new(b"this is a really good test".to_vec());

        match Hash::try_hash(&test, HashAlgorithm::SHA256) {
            Ok(hash) => match Hash::try_encode(&hash, Encoding::Base36) {
                Ok(serialised) => {
                    let serialised = serialised.get_string();
                    debug!("sha256 {serialised}");
                    assert_eq!(
                        serialised,
                        "i00ra1fzykfw5srqpoz7i14awapnka0jlewtkgcgtkgaaimyqyp"
                    );
                }
                Err(error) => debug!("serialisation error: {error:?}"),
            },
            Err(error) => debug!("hash error: {error:?}"),
        }
    }
}
