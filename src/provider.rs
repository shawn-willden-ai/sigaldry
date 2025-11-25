//! A provider is an object that provides access to a set of cryptographic primitives.
//! 
//! A provider generally corresponds to a hardware device like a Trusted Execution Environment (TEE) or a Secure Element (SE).
//! 
//! A provider is responsible for the following:
//! 
//! - Providing access to a set of cryptographic primitives.
//! - Managing the lifecycle of the cryptographic primitives.
//! - Providing a secure environment for the keys.
//! - Providing a secure environment for the operations.


pub trait Provider {

    // Generate keys, import keys, delete keys.
    // Attest keys.
    // Create operations, optionally pre-allocating resources.
}