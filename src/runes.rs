//! Runes are used to specify the security of a [`crate::provider::BindRune`], along a variety of
//! axes.

use alloc::{collections::btree_map::BTreeMap, vec::Vec};

use jiff::{Span, Zoned, civil::DateTime};

use crate::{
    error::{Error, Result},
    platform::PlatformAbstractions, provider::VariationType,
};

/// [`Rune`]s are used to specify the security of a [`crate::provider::BindRune`], along a variety
/// of axes.
///
/// Runes have two uses:
///
/// - Requirement specification: When calling [`crate::provider::Provider::forge`], the Runes
///   specify the minimum requiremens for a desired construction.  The returned `BindRune` will
///   satisfy all of the Runes, and will often exceed them.  If no available construction satisfies
///   the Runes, the request will be rejected with [`Error::UnsatisfiableRequirements`].
/// - Capability reporting:
///   - After a `BindRune` is forged, the `BindRune::schema` method can be called to report the
///     actual security properties of the `BindRune`.
///   - Constructions use `Rune`s to report the security properties they provide.
///
/// Most Runes are used for both specification and reporting but [`Rune::MessageLimit`],
/// [`Rune::TotalDataLimit`] and [`Rune::MessageSizeLimit`] are used only for specification.  After
/// forging, [`crate::provider::BindRune::schema`] returns [`Rune::EnforcedMessageLimit`],
/// [`Rune::EnforcedTotalDataLimit`] and [`Rune::EnforcedMessageSizeLimit`] to report the values
/// that will be enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rune {
    /// If provided, this [`Rune`] indicates that the [`crate::provider::BindRune`] uses a
    /// public/private key pair, allowing the public key to be distributed to other parties for
    /// encryption or verification.  If this `Rune` is not provided, the `BindRune` uses a symmetric
    /// key or a shared secret.
    PublicPrivateKeyPair,

    /// This [`Rune`] indicates that the [`crate::provider::BindRune`] provides specified number of
    /// security bits, assuming the key material is not compromised.
    ///
    /// In the case of a symmetric algorithm with no known weaknesses and a uniform key
    /// distribution, the security bits is the length of the key in bits.  If key distribution is
    /// non-uniform or there are known weaknesses that reduce the security, the value is reduced
    /// accordingly.
    ///
    /// For asymmetric algorithms the security bits is an estimated equivalent.  For example, in the
    /// case of RSA with a 2048-bit key, the estimated security bits is 112, per NIST SP 800-57 Part
    /// 1, table 2.  Where NIST doesn't provide an estimate other sources may be used, such as the
    /// various standards used by keylength.org.
    ///
    /// All security bit estimates are based on classical computing models, and may not apply to to
    /// quantum computing models.  To evaluate quantum computing resistance, examine the
    /// [`Rune::QuantumResistance`].
    ///
    /// When provided in a [`Provider::forge`] request, the caller will specify the desired minimum
    /// security bits, but the actual security bits of the construction may be higher and will be
    /// returned by [`crate::provider::BindRune::schema`].
    ///
    /// The value 256 indicates the operation provides ≥ 256 bits of security.
    SecurityBits(u8),

    /// If provided in a [`Provider::forge`] request, this property specifies the minimum number of
    /// messages that must be supported by the construction, without compromising security
    /// guarantees.  For example, AES-GCM with a random nonce can securely encrypt 2³² messages, per
    /// the NIST SP 800-38A.  After 2³² messages the probability of a nonce collision is 2⁻³²,
    /// increasing to 2⁻¹ after 2⁶⁴ messages.
    ///
    /// The number of messages that can be processed by the construction will usually be higher than
    /// the minimum number requested, and it's the construction's limit that will be enforced.
    ///
    /// If omitted in forge requests, the message limit defaults to 2¹⁶.
    ///
    /// The value 2¹²⁸ indicates that the message limit is unbounded.  Providing a value of 2¹²⁸ in
    /// a forge request will result in [`Error::InvalidMessageLimit`].
    MessageLimit(u128),

    /// If provided in a [`Provider::forge`] request, this property specifies both the minimum
    /// number of messages that must be supported by the construction, and the message count that
    /// will be enforced, even if the selected construction's limit is higher.
    ///
    /// This [`Rune`] is returned from [`crate::provider::BindRune::schema`] to report the actual
    /// number of messages that remain to be processed before the key key is invalidated.  When the
    /// value reaches zero, the [`crate::provider::BindRune`] is no longer valid.
    EnforcedMessageLimit(u128),

    /// If provided in a [`Provider::forge`] request, this property specifies the maximum size of a
    /// message, in bytes, that must be supported by the selected construction.  For example, if the
    /// construction is AES-GCM, the message size limit is 2³⁶ bytes because CTR mode has a 32-bit
    /// block counter.
    ///
    /// If omitted in forge requests, the message size limit defaults to 2¹⁶.
    ///
    /// The value 2¹²⁸ indicates that the message size limit is unbounded.  Providing a value of
    /// 2¹²⁸ in a forge request will result in [`Error::InvalidMessageSizeLimit`].
    MessageSizeLimit(u128),

    /// If provided in a [`Provider::forge`] request, this property specifies both the maximum size
    /// of a message, in bytes, that must be supported by the selectedconstruction, and the maximum
    /// message size that will be enforced, even if the selected construction's limit is higher.
    ///
    /// This [`Rune`] is returned from [`crate::provider::BindRune::schema`] to report the maximum
    /// message size that will be accepted.  When the value reaches zero, the
    /// [`crate::provider::BindRune`] is no longer valid.
    EnforcedMessageSizeLimit(u128),

    /// If provided in a [`Provider::forge`] request, this property specifies the maximum total
    /// amount of data, in bytes, that must be supported by the selected construction.  For example,
    /// if the construction is AES-CBC, the total data limit is 2⁶⁴ blocks, or 2⁶⁸ bytes, because
    /// ciphertext block collisions begin to appear with non-negligible probability.
    ///
    /// If omitted in forge requests, the total data limit defaults to 2³².
    ///
    /// The value 2¹²⁸ indicates that the total data limit is unbounded.  Providing a value of 2¹²⁸
    /// in a forge request will result in [`Error::InvalidTotalDataLimit`].
    TotalDataLimit(u128),

    /// If provided in a [`Provider::forge`] request, this property specifies both the maximum total
    /// amount of data, in bytes, that must be supported by the selected construction, and the total
    /// data limit that will be enforced, even if the selected construction's limit is higher.
    ///
    /// This [`Rune`] is returned from [`crate::provider::BindRune::schema`] to report the actual
    /// total data that remains to be processed before the key key is invalidated.  When the value
    /// reaches zero, the [`crate::provider::BindRune`] is no longer valid.
    EnforcedTotalDataLimit(u128),

    /// If provided, this property indicates that the operation provides confidentiality of the data
    /// until the specified `end_time`.  End times are estimates, and based on NIST SP 800-57 Part
    /// 1, table 2.  Where NIST doesn't provide an estimate other sources may be used, such as the
    /// various standards used by keylength.org.
    ///
    /// For all classical asymmetric algorithms, the end time is no later than Dec 31, 2035, per the
    /// US government's National Security Memorandum 10.
    Confidentiality { end_time: DateTime },

    /// If provided, this property indicates that the operation ensures the integrity of the data
    /// until the specified year. Years are estimates, and based on NIST SP 800-57 Part 1, table 2.
    /// Where NIST doesn't provide an estimate other sources may be used, such as the various
    /// standards used by keylength.org.
    ///
    /// For all classical asymmetric algorithms, `year` is 2035, per the US government's National
    /// Security Memorandum 10.
    Integrity { year: u16 },

    /// If provided, this property indicates that the operation provides authentication of the
    /// source of the data until the specified year.  Years are estimates, and based on NIST SP
    /// 800-57 Part 1, table 2.  Where NIST doesn't provide an estimate other sources may be used,
    /// such as the various standards used by keylength.org.
    ///
    /// For all classical asymmetric algorithms, `year` is 2035, per the US government's National
    /// Security Memorandum 10.
    Authentication { origin: OriginIdentity, year: u16 },

    /// If provided, this property indicates that the operation's security is valid for a specific
    /// period of time.  The period is specified by the begin and end milliseconds since the Unix
    /// epoch.
    ///
    /// Outside of the specified period the operation will be rejected.
    CryptoPeriod { begin: Zoned, end: Zoned },

    /// If provided, this property indicates that the operation's security is resistant to quantum
    /// computing attacks.
    QuantumResistance,

    /// Resistance to side channel attacks that can be exploited through software, such as timing
    /// attacks or cache timing attacks.
    ///
    /// If used in a [`Provider::forge`] request, all of the specified resistances must be provided
    /// or the request will be rejected.
    SoftwareSideChannelResistance(Vec<SoftwareSideChannelResistance>),

    /// Resistance to side channel attacks that require physical access to the hardware, such as
    /// power analysis or electromagnetic emissions.
    ///
    /// If used in a [`Provider::forge`] request, all of the specified resistances must be provided
    /// or the request will be rejected.
    HardwareSideChannelResistance(Vec<HardwareSideChannelResistance>),

    /// If provided, this property indicates that the operation and the keys it uses are kept in an
    /// isolated environment, separate from the caller's environment.  The degree of isolation is
    /// specified by the IsolationLevel enum.
    Isolated(IsolationLevel),

    /// If provided, the secure hardware has been evaluated and certified by one or more third
    /// parties for the purposes of protecting the operation and the keys it uses.  Details of the
    /// certifications are provided in the contained SecurityCertification objects.  A device's
    /// certification should not be included in the property set of an operation unless the
    /// certification applies to the operation.
    ///
    /// If used in a [`Provider::forge`] request, only one of the certifications need be provided by
    /// that available Sigaldry environment.  If none of the listed certifications are available,
    /// the request will be rejected.
    Certifications(Vec<SecurityCertification>),

    VariationStrategy(VariationStrategy)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariationStrategy {
    /// The variation is automatically generated by the [`seal`](`crate::provider::BindRune::seal`)
    /// operation and returned to the caller in the [`crate::provider::OperationResult`].  This is
    /// the default and recommended strategy.
    Automatic,

    /// The variation is provided by the caller.  The caller must provide a variation parameter of
    /// the specified type.  When [`VariationStrategy::CallerProvided`] is used in a
    /// [`Provider::forge`] request, the caller is indicating what type of variation parameter they
    /// are able to provide.  [`VariationType::Unique`] is the most difficult to provide, and
    /// [`VariationType::Arbitrary`] is the easiest, having no constraints on the values.
    /// 
    /// When [`VariationStrategy`] is returned from [`crate::provider::BindRune::schema`], it
    /// indicates the type of variation parameter that is required by the
    /// [`crate::provider::BindRune::seal`] operation.
    CallerProvided(VariationType),
}

impl Rune {
    /// Returns a numeric index for the variant, used for ordering by
    /// discriminant.
    fn variant_index(&self) -> u32 {
        match self {
            Rune::PublicPrivateKeyPair => 0,
            Rune::SecurityBits(_) => 1,
            Rune::MessageLimit(_) | Rune::EnforcedMessageLimit(_) => 2,
            Rune::MessageSizeLimit(_) | Rune::EnforcedMessageSizeLimit(_) => 3,
            Rune::TotalDataLimit(_) | Rune::EnforcedTotalDataLimit(_) => 4,
            Rune::Confidentiality { .. } => 8,
            Rune::Integrity { .. } => 9,
            Rune::Authentication { .. } => 10,
            Rune::CryptoPeriod { .. } => 11,
            Rune::QuantumResistance => 12,
            Rune::SoftwareSideChannelResistance(_) => 13,
            Rune::HardwareSideChannelResistance(_) => 14,
            Rune::Isolated(_) => 15,
            Rune::Certifications(_) => 16,
            Rune::VariationStrategy(_) => 17,
        }
    }
}

/// Side channel resistances that can be exploited through software attacks, typically by malicious
/// code running on the same system or by an attacker who can measure timing or other
/// software-observable characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareSideChannelResistance {
    /// The operation is constant time and therefore resistant to timing attacks.
    ConstantTime,

    /// The operation is cache timing resistant, meaning that it is resistant to cache timing
    /// attacks executed from the client environment.  In some cases this may be achieved by using a
    /// cache-timing resistant implementation of the algorithm.  In other cases it may be achieved
    /// by using hardware isolation that ensures there are no caches shared between the operation
    /// and the caller's environments.  For example, [`IsolationLevel::DiscreteCpu`].
    CacheTimingResistant,
}

/// Side channel resistances that require physical access to the hardware to exploit, such as power
/// analysis or electromagnetic emissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareSideChannelResistance {
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

/// The level of isolation provided by the operation, including keys and
/// computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// The operation is not isolated, running in the same process as the
    /// application.
    SameProcess,

    /// The operation is isolated in a separate process running on the same
    /// machine and under the same operating system as the caller.  The
    /// degree of isolation provided depends on the context and is presumed
    /// to be understood by the caller.
    SeparateProcess,

    /// The operation is isolated in a virtual machine that is running on the
    /// same CPU as the caller but not in the same operating system.  A full
    /// compromise of the client's host operating system will not compromise
    /// the isolation.  However, there may still be side channel leakages
    /// through interactions between VMs or through the shared CPU hardware.
    VirtualMachine,

    /// The operation is isolated in a discrete CPU that is physically separate
    /// from the caller's CPU.  This is the strongest form of isolation, and
    /// is the only way to ensure that the operation is not subject to
    /// software-based side channel attacks.  It may provide protection
    /// against hardware side channel attacks, if the discrete CPU is designed
    /// to be hardened against such attacks.
    DiscreteCpu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityCertification;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    runes: Vec<Rune>,
}

impl Schema {}

const DEFAULT_RUNES: [Rune; 3] = [
    // The default message limit is 2¹⁶.
    Rune::MessageLimit(2_u128.pow(16)),
    // The default message size limit is 2¹⁶.
    Rune::MessageSizeLimit(2_u128.pow(16)),
    // The default total data limit is 2³².
    Rune::TotalDataLimit(2_u128.pow(32)),
];

pub struct SchemaBuilder {
    runes: BTreeMap<u32, Rune>,
}

/// Helper macro to push an item to a vector-valued Rune variant, creating the variant if needed.
/// Duplicates are filtered out.
macro_rules! push_to_vec_rune {
    ($runes:expr, $variant:ident, $item:expr) => {{
        let item = $item;
        let rune = Rune::$variant(vec![item]);
        let index = rune.variant_index();
        match $runes.insert(index, rune) {
            Some(Rune::$variant(mut vec)) => {
                if !vec.contains(&item) {
                    vec.push(item);
                }
                $runes.insert(index, Rune::$variant(vec));
            }
            None => { /* Already inserted above */ }
            _ => unreachable!("Got something other than the rune at its variant index"),
        }
    }};
}

impl SchemaBuilder {
    pub fn new() -> Self {
        Self {
            runes: DEFAULT_RUNES.iter().map(|rune| (rune.variant_index(), rune.clone())).collect(),
        }
    }

    pub fn build(self) -> Schema {
        Schema { runes: self.runes.into_values().collect() }
    }

    /// Requires that the [`crate::provider::BindRune`] uses a public/private key pair, allowing the
    /// public key to be distributed to other parties for encryption or verification.  If this
    /// [`Rune`] is not provided, the `BindRune` uses a symmetric key or a shared secret.
    pub fn public_private_key_pair(mut self) -> Self {
        let rune = Rune::PublicPrivateKeyPair;
        self.runes.insert(rune.variant_index(), rune);
        self
    }

    /// Requires that the [`crate::provider::BindRune`] provides confidentiality for the specified
    /// amount of time, from the moment of key generation.  Confidentiality years are estimates,
    /// based on NIST SP 800-57 Part 1, table 2 or similar sources.  They are best-estimate
    /// projections based on the current state of the art.
    ///
    /// Callers should endeavor to specify the shortest period of time that they can tolerate.  At
    /// present, the confidentiality period is only used to select the appropriate construction, but
    /// in the future it may be used in other ways, for example to identify keys that need rotation.
    pub fn confidentiality<P: PlatformAbstractions>(mut self, duration: Span) -> Result<Self> {
        let end_time =
            P::get_current_time().datetime().checked_add(duration).map_err(Error::from)?;
        let rune = Rune::Confidentiality { end_time };
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn security_bits(mut self, security_bits: u8) -> Self {
        let rune = Rune::SecurityBits(security_bits);
        self.runes.insert(rune.variant_index(), rune);
        self
    }

    pub fn message_limit(mut self, message_limit: u128) -> Result<Self> {
        if message_limit == u128::MAX {
            return Err(Error::InvalidMessageLimit(format!("Message limit cannot be unbounded")));
        }
        let rune = Rune::MessageLimit(message_limit);
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn enforced_message_limit(mut self, enforced_message_limit: u128) -> Result<Self> {
        if enforced_message_limit == u128::MAX {
            return Err(Error::InvalidMessageLimit(format!("Message limit cannot be unbounded")));
        }
        let rune = Rune::EnforcedMessageLimit(enforced_message_limit);
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn message_size_limit(mut self, message_size_limit: u128) -> Result<Self> {
        if message_size_limit == u128::MAX {
            return Err(Error::InvalidMessageSizeLimit(format!(
                "Message size limit cannot be unbounded"
            )));
        }
        let rune = Rune::MessageSizeLimit(message_size_limit);
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn enforced_message_size_limit(
        mut self,
        enforced_message_size_limit: u128,
    ) -> Result<Self> {
        if enforced_message_size_limit == u128::MAX {
            return Err(Error::InvalidMessageSizeLimit(format!(
                "Message size limit cannot be unbounded"
            )));
        }
        let rune = Rune::EnforcedMessageSizeLimit(enforced_message_size_limit);
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn total_data_limit(mut self, total_data_limit: u128) -> Result<Self> {
        if total_data_limit == u128::MAX {
            return Err(Error::InvalidTotalDataLimit(format!(
                "Total data limit cannot be unbounded"
            )));
        }
        let rune = Rune::TotalDataLimit(total_data_limit);
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn enforced_total_data_limit(mut self, enforced_total_data_limit: u128) -> Result<Self> {
        if enforced_total_data_limit == u128::MAX {
            return Err(Error::InvalidTotalDataLimit(format!(
                "Total data limit cannot be unbounded"
            )));
        }
        let rune = Rune::EnforcedTotalDataLimit(enforced_total_data_limit);
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn crypto_period(mut self, begin: Zoned, end: Zoned) -> Result<Self> {
        if begin >= end {
            return Err(Error::InvalidCryptoPeriod(format!(
                "Begin {} must be before end {}",
                begin, end
            )));
        }
        let rune = Rune::CryptoPeriod { begin, end };
        self.runes.insert(rune.variant_index(), rune);
        Ok(self)
    }

    pub fn quantum_resistance(mut self, quantum_resistance: bool) -> Self {
        if quantum_resistance {
            let rune = Rune::QuantumResistance;
            self.runes.insert(rune.variant_index(), rune);
        } else {
            self.runes.remove(&Rune::QuantumResistance.variant_index());
        }
        self
    }

    pub fn software_side_channel_resistance(
        mut self,
        resistance: SoftwareSideChannelResistance,
    ) -> Self {
        push_to_vec_rune!(self.runes, SoftwareSideChannelResistance, resistance);
        self
    }

    pub fn hardware_side_channel_resistance(
        mut self,
        resistance: HardwareSideChannelResistance,
    ) -> Self {
        push_to_vec_rune!(self.runes, HardwareSideChannelResistance, resistance);
        self
    }

    pub fn isolated(mut self, isolation_level: IsolationLevel) -> Self {
        let rune = Rune::Isolated(isolation_level);
        self.runes.insert(rune.variant_index(), rune);
        self
    }

    pub fn certification(mut self, certification: SecurityCertification) -> Self {
        push_to_vec_rune!(self.runes, Certifications, certification);
        self
    }
}
