#![no_std]
#[macro_use]
extern crate alloc;

pub mod error;
mod platform;

// Traits related to encryption and decryption.
pub mod block_cipher;
pub mod hybrid_encryption;
pub mod stream_cipher;

// Traits related to signing and verification.
pub mod signature;

// Traits related to key derivation.
pub mod kdf;

// Traits related to hash functions.
pub mod hash_function;

// Traits related to key agreement.
pub mod key_agreement;

// Traits related to message authentication codes.
pub mod message_authentication_code;

// Traits related to sponge functions.
pub mod sponge_function;

pub mod runes;

pub mod construction;

pub mod provider;

pub trait CryptographicPrimitive {
    fn security_properties(&self) -> runes::Schema;
}
