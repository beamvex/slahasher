# slahasher

A Rust library providing hashing functions.

## Features

- SHA-256
- Keccak-256
- Keccak-384
- Keccak-512
- RIPEMD-160
- Base encoding support via base_xx

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
slahasher = "0.5.0"
```

## Usage

```rust
use std::sync::Arc;

use base_xx::{ByteVec, Encoding};
use slahasher::{Hash, HashAlgorithm};

fn main() -> Result<(), base_xx::SerialiseError> {
    let bytes = Arc::new(ByteVec::new(Arc::new(vec![1, 2, 3])));

    let hash = Hash::try_hash(bytes, HashAlgorithm::SHA256)?;
    let encoded = hash.try_to_byte_vec()?.try_encode(Encoding::Base36)?;

    println!("{}", encoded);
    Ok(())
}
```

Decoding from an encoded string back into a `Hash`:

```rust
use std::sync::Arc;

use base_xx::{EncodedString, Encoding};
use slahasher::Hash;

fn main() -> Result<(), base_xx::SerialiseError> {
    let encoded = EncodedString::new(Encoding::Base36, "...".to_string());
    let hash = Hash::try_decode(encoded)?;
    let _hash_bytes = Arc::clone(hash.get_bytes());
    Ok(())
}
```

Documentation is available at [docs.rs/slahasher](https://docs.rs/slahasher)

## License

This project is licensed under the MIT License.

## Contributing

Issues and pull requests are welcome on GitHub at https://github.com/beamvex/slahasher

## Authors

- Robert Forster (robert.forster@beamvex.com)
