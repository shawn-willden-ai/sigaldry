// Traits related to encryption and decryption.
pub mod block_cipher;
pub mod stream_cipher;
pub mod hybrid_encryption;

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

pub mod security_properties;

pub mod construction;

pub mod provider;

pub trait CryptographicPrimitive {
    fn security_properties(&self) -> security_properties::SecurityPropertySet;
}

