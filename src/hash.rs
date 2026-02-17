//use crate::hashing::Keccak256;
//use crate::hashing::Keccak384;
//use crate::hashing::Ripemd160;
use crate::Sha256;

use base_xx::ByteVec;
use base_xx::EncodedString;
use base_xx::Encoding;
use base_xx::SerialiseError;
use base_xx::decodable;
use base_xx::encodable;

use crate::HashAlgorithm;

/// A cryptographic hash value with its associated algorithm.
///
/// This type represents the result of applying a cryptographic hash function to some data.
/// It stores both the resulting hash value and the algorithm used to create it.
#[derive(Debug)]
pub struct Hash {
    /// The algorithm used to create this hash
    algorithm: HashAlgorithm,
    /// The raw bytes of the hash value
    bytes: Vec<u8>,
}

impl Hash {
    /// Creates a new hash value with the specified algorithm and bytes.
    ///
    /// # Arguments
    /// * `algorithm` - The hash algorithm used to create this hash
    /// * `bytes` - The raw hash value bytes
    #[must_use]
    pub const fn new(algorithm: HashAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns a reference to the raw hash value bytes.
    #[must_use]
    pub const fn get_bytes(&self) -> &Vec<u8> {
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
    pub fn verify(&self, bytes: &[u8]) -> bool {
        match self.algorithm {
            HashAlgorithm::SHA256 => {
                let hash: Self = Sha256::from_bytes(bytes).into();
                hash.get_bytes() == self.get_bytes()
            }
            HashAlgorithm::KECCAK256 | HashAlgorithm::KECCAK384 | HashAlgorithm::RIPEMD160 => {
                //let hash: Self = Ripemd160::from_bytes(bytes).into();
                //hash.get_bytes() == self.get_bytes()
                false
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
        bytes.extend_from_slice(&self.bytes);
        Ok(bytes)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, SerialiseError> {
        let algorithm = HashAlgorithm::try_from(bytes[0]);
        match algorithm {
            Err(error) => Err(error),
            Ok(algorithm) => {
                let bytes = bytes[1..].to_vec();
                Ok(Self::new(algorithm, bytes))
            }
        }
    }

    pub fn try_hash(byte_vec: &ByteVec, algorithm: HashAlgorithm) -> Result<Self, SerialiseError> {
        match algorithm {
            HashAlgorithm::SHA256 => Self::try_hash_sha256(byte_vec),
            HashAlgorithm::KECCAK256 | HashAlgorithm::KECCAK384 | HashAlgorithm::RIPEMD160 => Err(
                SerialiseError::new("Unsupported hash algorithm".to_string()),
            ),
        }
    }

    pub fn try_hash_sha256(byte_vec: &ByteVec) -> Result<Self, SerialiseError> {
        Ok(Self::new(
            HashAlgorithm::SHA256,
            Sha256::from_bytes(byte_vec.get_bytes()).get_bytes(),
        ))
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
        match Self::try_from_bytes(&value.get_bytes()) {
            Ok(hash) => Ok(hash),
            Err(err) => Err(err),
        }
    }
}

encodable!(Hash);
decodable!(Hash);

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hash() {
        let bytes = ByteVec::new(vec![1, 2, 3]);
        match Hash::try_hash(&bytes, HashAlgorithm::SHA256) {
            Ok(hash) => match hash.try_encode(Encoding::Base36) {
                Ok(hash_ss) => {
                    let hash_str = hash_ss.get_string();
                    slogger::debug!("hash: {hash_str}");
                    slogger::debug!("hash debug: {hash:?}");
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
