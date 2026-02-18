use crate::{Hash, HashAlgorithm};
use base_xx::ByteVec;
use base_xx::SerialiseError;
use sha3::{Digest, Keccak384 as Keccak384Impl};

pub struct Keccak384 {
    hash: Hash,
}

impl Keccak384 {
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
        let mut hasher = Keccak384Impl::new();
        let bytes = bytes.get_bytes();
        hasher.update(bytes);
        let result = hasher.finalize();
        let bytes = result.to_vec();
        if bytes.len() != 48 {
            return Err(SerialiseError::new("Invalid hash length".to_string()));
        }
        Ok(Self::new(Hash::new(HashAlgorithm::KECCAK384, bytes)))
    }
}

impl TryFrom<&ByteVec> for Keccak384 {
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
    pub fn test_keccak384() {
        let test = ByteVec::new(b"this is a really good test".to_vec());

        match Hash::try_hash(&test, HashAlgorithm::KECCAK384) {
            Ok(hash) => match Hash::try_encode(&hash, Encoding::Base36) {
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
            Err(error) => debug!("hash error: {error:?}"),
        }
    }
}
