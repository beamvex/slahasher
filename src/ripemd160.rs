use crate::hasher;
use crate::{Hash, HashAlgorithm};
use base_xx::ByteVec;
use base_xx::SerialiseError;
use ripemd::{Digest, Ripemd160 as Ripemd160Impl};

pub struct Ripemd160 {}

impl Ripemd160 {
    /// Creates a `Keccak256` hash from the provided bytes.
    ///
    /// # Errors
    ///
    /// Returns `SerialiseError` if the computed hash is not 32 bytes.
    #[must_use = "the computed hash is returned in the Ok value"]
    pub fn try_from_bytes(bytes: &ByteVec) -> Result<Hash, SerialiseError> {
        let mut hasher = Ripemd160Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let clone = hasher.clone();
        let result = clone.finalize();

        let _result2 = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 20 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }
        Ok(Hash::new(HashAlgorithm::RIPEMD160, bytes))
    }
}

impl hasher::Hasher for Ripemd160 {
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
    pub fn test_ripemd160() {
        let test = ByteVec::new(b"this is a really good test".to_vec());

        match Hash::try_hash(&test, HashAlgorithm::RIPEMD160) {
            Ok(hash) => match Hash::try_encode(&hash, Encoding::Base36) {
                Ok(serialised) => {
                    let serialised = serialised.get_string();
                    debug!("sha256 {serialised}");
                    assert_eq!(serialised, "2dboul7pklshdt421fslt94vk6qkuamg0");
                }
                Err(error) => debug!("serialisation error: {error:?}"),
            },
            Err(error) => debug!("hash error: {error:?}"),
        }
    }
}
