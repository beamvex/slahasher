use crate::Hash;
use base_xx::ByteVec;
use base_xx::SerialiseError;

pub trait Hasher {
    /// Computes a hash of the provided bytes.
    ///
    /// # Errors
    /// * `SerialiseError` - If hashing fails (for example, due to an error converting the input
    ///   bytes to the internal hash representation)
    fn try_hash(byte_vec: &ByteVec) -> Result<Hash, SerialiseError>;
}
