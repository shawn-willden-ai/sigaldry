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

use crate::security_properties::SecurityPropertySet;


pub trait Provider {

    // Most generic interface:
    fn generate_key(&self, desired_properties: SecurityPropertySet) -> Result<Key, Error>;
    fn create_sealing_operation(&self, key: &Key) -> Result<SealingOperation, Error>;
    fn create_unsealing_operation(&self, key: &Key) -> Result<UnsealingOperation, Error>;

    // Specified-construction interface:
    fn generate_symmetric_authentication_key(&self, desired_properties: SecurityPropertySet, ) -> Result<SymmetricAuthenticationKey, Error>;
    fn generate_symmetric_enryption_key(&self, desired_properties: SecurityPropertySet, construction: &'static str) -> Result<SymmetricEncryptionKey, Error>;
    fn generate_symmetric_master_key(&self, desired_properties: SecurityPropertySet, construction: &'static str) -> Result<SymmetricMasterKey, Error>;
    fn generate_signing_key(&self, desired_properties: SecurityPropertySet, construction: &'static str) -> Result<SigningKeyPair, Error>;
    fn generate_hybrid_encryption_key(&self, desired_properties: SecurityPropertySet, construction: &'static str) -> Result<HybridEncryptionKeyPair, Error>;

    fn create_symmetric_authentication_operation(&self, key: &SymmetricAuthenticationKey) -> Result<SymmetricAuthenticationOperation, Error>;
    fn create_symmetric_enryption_operation(&self, key: &SymmetricEncryptionKey) -> Result<SymmetricEncryptionOperation, Error>;
    fn create_symmetric_master_operation(&self, key: &SymmetricMasterKey) -> Result<SymmetricMasterOperation, Error>;
    fn create_signing_operation(&self, key: &SigningKeyPair) -> Result<SigningOperation, Error>;
    fn create_hybrid_encryption_operation(&self, key: &HybridEncryptionKeyPair) -> Result<HybridEncryptionOperation, Error>;

    // Low-level interface:
    fn generate_symmetric_key(&self, desired_properties: SecurityPropertySet, algorithm: Algorithm) -> Result<SymmetricKey, Error>;
}