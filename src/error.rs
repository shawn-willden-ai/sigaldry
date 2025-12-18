use alloc::string::String;

use crate::runes::Schema;

pub enum Error {
    /// The requested schema cannot be satisfied by any available construction.
    UnsatisfiableRequirements(Schema),
    /// The requested label was not found.
    UnknownLabel,
    /// A communication error occurred.
    CommunicationError(String),
    /// An internal error occurred.
    InternalError(String),
    /// The provided variation parameter is invalid for the [`BindRune`].
    InvalidVariation(String),
    /// The provided message limit is invalid.
    InvalidMessageLimit(String),
    /// The provided message size limit is invalid.
    InvalidMessageSizeLimit(String),
    /// The provided total data limit is invalid.
    InvalidTotalDataLimit(String),
    /// The provided crypto period is invalid.
    InvalidCryptoPeriod(String),
    /// The provided message exceeds the message size limit.
    MessageTooLong(String),
    /// The total data limit of the [`crate::provider::BindRune`] has been exceeded.
    TotalDataTooLong(String),
    /// The [`crate::provider::BindRune`] is not valid yet.   
    CryptoPeriodTooSoon(String),
    /// The [`crate::provider::BindRune`] is no longer valid.
    CryptoPeriodTooLate(String),
    /// The provided variation parameter is invalid.
    VariationInvalid(String),
    /// The provided variation type is of a type that is not supported by the
    /// [`crate::provider::BindRune`].
    VariationTypeInvalid(String),
}

impl From<jiff::Error> for Error {
    fn from(error: jiff::Error) -> Self {
        Error::InternalError(format!("Time error:{}", error))
    }
}

pub type Result<T> = core::result::Result<T, Error>;
