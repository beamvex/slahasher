use crate::Keccak256;
use crate::Keccak384;
use crate::Keccak512;
use crate::Ripemd160;
use crate::Sha256;
use crate::hasher::Hasher;

use base_xx::ByteVec;
use base_xx::SerialiseError;
use base_xx::byte_vec::Encodable;
use base_xx::encoded_string::Decodable;

use crate::HashAlgorithm;

/// A cryptographic hash value with its associated algorithm.
///
/// This type represents the result of applying a cryptographic hash function to some data.
/// It stores both the resulting hash value and the algorithm used to create it.
#[derive(Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct Hash {
    /// The algorithm used to create this hash
    algorithm: HashAlgorithm,
    /// The raw bytes of the hash value
    bytes: ByteVec,
}

impl Hash {
    /// Creates a new hash value with the specified algorithm and bytes.
    ///
    /// # Arguments
    /// * `algorithm` - The hash algorithm used to create this hash
    /// * `bytes` - The raw hash value bytes
    #[must_use]
    pub const fn new(algorithm: HashAlgorithm, bytes: ByteVec) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns a reference to the raw hash value bytes.
    #[must_use]
    pub const fn get_bytes(&self) -> &ByteVec {
        &self.bytes
    }

    /// Returns the algorithm used to create this hash.
    #[must_use]
    pub const fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Verifies that this hash matches the hash of the provided bytes.
    ///
    /// # Arguments
    /// * `bytes` - The bytes to verify against this hash
    ///
    /// # Returns
    /// `true` if the hash of the provided bytes matches this hash, `false` otherwise
    #[must_use]
    pub fn verify(&self, bytes: &ByteVec) -> bool {
        match self.algorithm {
            HashAlgorithm::SHA256 => {
                Sha256::try_hash(bytes).is_ok_and(|hash| hash.get_bytes() == self.get_bytes())
            }
            HashAlgorithm::KECCAK512 => {
                Keccak512::try_hash(bytes).is_ok_and(|hash| hash.get_bytes() == self.get_bytes())
            }
            HashAlgorithm::KECCAK256 => {
                Keccak256::try_hash(bytes).is_ok_and(|hash| hash.get_bytes() == self.get_bytes())
            }
            HashAlgorithm::KECCAK384 => {
                Keccak384::try_hash(bytes).is_ok_and(|hash| hash.get_bytes() == self.get_bytes())
            }
            HashAlgorithm::RIPEMD160 => {
                Ripemd160::try_hash(bytes).is_ok_and(|hash| hash.get_bytes() == self.get_bytes())
            }
        }
    }

    fn try_as_bytes(&self) -> Result<Vec<u8>, SerialiseError> {
        let mut bytes = vec![];
        let algorithm: Result<u8, SerialiseError> = self.algorithm.try_into();
        match algorithm {
            Err(error) => return Err(error),
            Ok(algorithm) => bytes.push(algorithm),
        }
        bytes.extend_from_slice(self.bytes.get_bytes());
        Ok(bytes)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SerialiseError> {
        let algorithm = HashAlgorithm::try_from(bytes[0]);
        match algorithm {
            Err(error) => Err(error),
            Ok(algorithm) => {
                let bytes = bytes[1..].to_vec();
                Ok(Self::new(algorithm, ByteVec::new(bytes)))
            }
        }
    }
    /// Computes a hash of the provided bytes using the given algorithm.
    ///
    /// # Errors
    /// Returns `SerialiseError` if hashing fails.
    pub fn try_hash(byte_vec: &ByteVec, algorithm: HashAlgorithm) -> Result<Self, SerialiseError> {
        match algorithm {
            HashAlgorithm::SHA256 => Sha256::try_hash(byte_vec),
            HashAlgorithm::KECCAK256 => Keccak256::try_hash(byte_vec),
            HashAlgorithm::KECCAK384 => Keccak384::try_hash(byte_vec),
            HashAlgorithm::KECCAK512 => Keccak512::try_hash(byte_vec),
            HashAlgorithm::RIPEMD160 => Ripemd160::try_hash(byte_vec),
        }
    }
}

impl TryFrom<&Hash> for ByteVec {
    type Error = SerialiseError;
    fn try_from(value: &Hash) -> Result<Self, Self::Error> {
        match value.try_as_bytes() {
            Ok(bytes) => Ok(Self::new(bytes)),
            Err(error) => Err(error),
        }
    }
}

impl TryFrom<ByteVec> for Hash {
    type Error = SerialiseError;
    fn try_from(value: ByteVec) -> Result<Self, Self::Error> {
        match Self::try_from_bytes(value.get_bytes()) {
            Ok(hash) => Ok(hash),
            Err(err) => Err(err),
        }
    }
}

impl Encodable for Hash {}
impl Decodable for Hash {}

#[cfg(test)]
mod tests {

    use super::*;

    use base_xx::Encoding;
    use base_xx::byte_vec::Encodable;

    #[test]
    fn test_hash() {
        let bytes = ByteVec::new(vec![1, 2, 3]);
        match Hash::try_hash(&bytes, HashAlgorithm::SHA256) {
            Ok(hash) => match Hash::try_encode(&hash, Encoding::Base36) {
                Ok(hash_ss) => {
                    let hash_str = hash_ss.get_string();
                    slogger::debug!("hash: {hash_str}");
                    slogger::debug!("hash debug: {hash:?}");
                    assert_eq!(
                        hash_str,
                        "hwis74tcngndmvw8t0jaf8baow2455synbsyr8u6vfvfvi6mgld"
                    );
                }
                Err(error) => slogger::debug!("serialstring error: {error:?}"),
            },
            Err(error) => slogger::debug!("hash error: {error:?}"),
        }

        /*
        let hash_str: SerialString = Base36::try_from(Bytes::try_from(&hash).unwrap())
            .unwrap()
            .into();
        let hash_str = hash_str.get_string();
        slogger::debug!("hash: {hash_str}");
        slogger::debug!("hash debug: {hash:?}");

        let hash: Hash = Keccak384::from_bytes(&bytes).into();

        let hash_str: SerialString = Base36::try_from(Bytes::try_from(&hash).unwrap())
            .unwrap()
            .into();
        let hash_str = hash_str.get_string();
        slogger::debug!("hash: {hash_str}");
        slogger::debug!("hash debug: {hash:?}");
        */
    }
}
