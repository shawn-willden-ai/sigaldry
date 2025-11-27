
/// Security properties of a cryptographic primitive.
///
/// Security properties are used to specify the security of a cryptographic primitive or
/// construction, along a variety of axes.  In many cases the security properties are only an
/// estimate, such as the
/// number of security bits, or the year associated with the the confidentiality property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityProperty {
    /// If provided, this property indicates that the operation uses a public/private key pair,
    /// allowing the public key to be distriuted to other parties for encryption or verification.
    /// If this property is not provided, the operation uses a symmetric key or a shared secret.
    PublicPrivateKeyPair,

    /// If provided, this property indicates that the operation uses a shared secret.
    SharedSecret,
    
    /// If provided, this property indicates that the operation provides confidentiality of the
    /// Estimated number of security bits, assuming the key material is not compromised.
    /// 
    /// In the case of a symmetric block cipher with no known weaknesses and a uniform key
    /// distribution, the security bits is the length of the key in bits.  When there are known
    /// weaknesses that reduce the security, the security bits is reduced accordingly.  For
    /// algorithms and constructions other than symmetric block ciphers, the security bits is an
    /// estimated equivalent.  For example, in the case of RSA with a 2048-bit key, the estimated
    /// security bits is 112, per the NIST SP 800-57 Part 1, table 2.
    /// 
    /// All security bit estimates are based on classical computing models, and may not apply to
    /// to quantum computing models.  To evaluate quantum computing resistance, examine the
    /// QuantumResistance property.
    /// 
    /// Note that during key generation, the caller will specify the desired minimum security
    /// bits, but the actual security bits may be higher.  The actual estimate will be provided in
    /// the property set of the key.
    SecurityBits(u16),

    /// If provided, this property indicates that the operation can process a maximum number of
    /// messages.  This is typically used to limit the number of messages that can be processed
    /// by the operation, to prevent abuse or resource exhaustion.  For example, if the operation
    /// is a symmetric encryption operation, the message limit is the maximum number of messages
    /// that can be encrypted by the operation before security guarantees may be compromised.
    /// 
    /// Note that during key generation, the caller will specify the desired message limit, but the
    /// actual message limit may be higher.  The actual estimate will be provided in the property
    /// set of the key, and will decline as the key is used.
    MessageLimit(MessageLimit),

    /// If provided, this property indicates that the operation can process a maximum total amount
    /// of data, in bytes.  This is used to limit the total amount of data that can be processed
    /// by the operation.  For example, if the operation is a symmetric encryption operation, the
    /// total data limit is the maximum total amount of data that can be encrypted by the
    /// operation before security guarantees may be compromised.
    /// 
    /// Note that during key generation, the caller will specify the desired total data limit, but the
    /// actual total data limit may be higher.  The actual estimate will be provided in the property
    /// set of the key, and will decline as the key is used.
    TotalDataLimit(TotalDataLimit),

    /// If provided, this property indicates that the operation provides confidentiality of the
    /// data.
    Confidentiality,

    /// If provided, this property indicates that the operation ensures the integrity of the data.
    Integrity,

    /// If provided, this property indicates that the operation provides authentication of the
    /// source of the data.
    Authentication(OriginIdentity),

    /// If provided, this property indicates that the operation's security is resistant to quantum
    /// computing attacks.
    QuantumResistance,

    /// Resistance to side channel attacks that can be exploited through software, such as timing
    /// attacks or cache timing attacks.
    SoftwareSideChannelResistance(SoftwareSideChannelResistances),

    /// Resistance to side channel attacks that require physical access to the hardware, such as
    /// power analysis or electromagnetic emissions.
    HardwareSideChannelResistance(HardwareSideChannelResistances),

    /// If provided, this property indicates that the operation and the keys it uses are kept in
    /// an isolated environment, separate from the caller's environment.  The degree of isolation
    /// is specified by the IsolationLevel enum.
    Isolated(IsolationLevel),

    /// If provided, the secure hardware has been evaluated and certified by one or more third
    /// parties for the purposes of protecting the operation and the keys it uses.  Details of the
    /// certifications are provided in the contained SecurityCertification objects.  A device's
    /// certification should not be included in the property set of an operation unless the
    /// certification applies to the operation.
    Certifications(Vec<SecurityCertification>)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MessageLimit {
    Unbounded,
    Limited(u128),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TotalDataLimit {
    Unbounded,
    Limited(u128),
}

/// Side channel resistances that can be exploited through software attacks, typically by
/// malicious code running on the same system or by an attacker who can measure timing or other
/// software-observable characteristics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoftwareSideChannelResistances {
    /// The operation is constant time and therefore resistant to timing attacks.
    ConstantTime,

    /// The operation is cache timing resistant, meaning that it is resistant to cache timing
    /// attacks executed from the client environment.  In some cases this may be achieved by using
    /// a cache-timing resistant implementation of the algorithm.  In other cases it may be
    /// achieved by using hardware isolation that ensures there are no caches shared between the
    /// operation and the caller's environments.  For example, [`IsolationLevel::DiscreteCpu`].
    CacheTimingResistant,
}

/// Side channel resistances that require physical access to the hardware to exploit, such as
/// power analysis or electromagnetic emissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareSideChannelResistances {
    /// The operation is power analysis resistant (including both differential power analysis and
    /// simple power analysis), meaning that it is resistant to power analysis attacks executed
    /// against the device that hosts they key and computation.  In some cases this may be achieved
    /// by using a power analysis resistant implementation of the algorithm.  In other cases it may
    /// be achieved by using a hardware design that is resistant to power analysis attacks.
    PowerAnalysisResistant,

    /// The operation is electromagnetic side channel resistant, meaning that it is resistant to
    /// electromagnetic side channel attacks executed against the device that hosts they key and
    /// computation.  It is generally a hardware design that is shielded or otherwise resistant to
    /// electromagnetic side channel attacks.
    EmSideChannelResistant,
}

/// The level of isolation provided by the operation, including keys and computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationLevel {
    /// The operation is isolated in a separate process running on the same machine and under the
    /// same operating system as the caller.  The degree of isolation provided depends on the
    /// context and is presumed to be understood by the caller.
    SeparateProcess,

    /// The operation is isolated in a virtual machine that is running on the same CPU as the
    /// caller but not in the same operating system.  A full compromise of the client's host
    /// operating system will not compromise the isolation.  However, there may still be side
    /// channel leakages through interactions between VMs or through the shared CPU hardware.
    VirtualMachine,

    /// The operation is isolated in a discrete CPU that is physically separate from the caller's
    /// CPU.  This is the strongest form of isolation, and is the only way to ensure that the
    /// operation is not subject to software-based side channel attacks.  It may provide
    /// protection against hardware side channel attacks, if the discrete CPU is designed to be
    /// hardened against such attacks.
    DiscreteCpu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCertification;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPropertySet {
    properties: Vec<SecurityProperty>,
}

impl SecurityPropertySet {
    pub fn new(properties: Vec<SecurityProperty>) -> Self {
        Self { properties }
    }

    pub fn properties(&self) -> &[SecurityProperty] {
        &self.properties
    }
}

