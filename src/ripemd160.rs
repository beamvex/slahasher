use crate::{Hash, HashAlgorithm};
use base_xx::ByteVec;
use base_xx::SerialiseError;
use ripemd::{Digest, Ripemd160 as Ripemd160Impl};

pub struct Ripemd160 {
    hash: Hash,
}

impl Ripemd160 {
    #[must_use]
    pub const fn new(hash: Hash) -> Self {
        Self { hash }
    }

    #[must_use]
    pub fn get_hash(self) -> Hash {
        self.hash
    }

    #[must_use]
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Creates a `Keccak256` hash from the provided bytes.
    ///
    /// # Errors
    ///
    /// Returns `SerialiseError` if the computed hash is not 32 bytes.
    #[must_use = "the computed hash is returned in the Ok value"]
    pub fn try_from_bytes(bytes: &ByteVec) -> Result<Self, SerialiseError> {
        let mut hasher = Ripemd160Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let result = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 20 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }
        Ok(Self::new(Hash::new(HashAlgorithm::KECCAK384, bytes)))
    }
}

impl TryFrom<&ByteVec> for Ripemd160 {
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
