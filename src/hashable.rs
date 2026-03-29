use std::sync::Arc;

use base_xx::{SerialiseError, byte_vec::TryIntoByteVec};

use crate::{Hash, HashAlgorithm};

/// Hashable trait
pub trait Hashable
where
    Self: TryIntoByteVec,
{
    /// Encodes this type using the specified `Encoding`.
    ///
    /// # Parameters
    /// * `value` - The value to encode
    /// * `encoding` - The encoding to use when encoding this type.
    ///
    /// # Returns
    /// A `Result` containing the encoded string if successful, or a `SerialiseError` if an error occurs.
    ///
    /// # Errors
    /// * `SerialiseError` - If the specified encoding is unsupported or an error occurs during serialisation.
    #[must_use = "The result of this function is a `Result` containing the encoded string if successful, or a `SerialiseError` if an error occurs."]
    fn try_hash(value: Arc<Self>, algorithm: HashAlgorithm) -> Result<Arc<Hash>, SerialiseError> {
        match Self::try_into_byte_vec(value) {
            Ok(bytes) => Hash::try_hash(bytes, algorithm),
            Err(error) => Err(error),
        }
    }
}
