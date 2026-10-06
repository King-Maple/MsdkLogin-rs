use crate::{Channel, LoginState};
use std::{fmt, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdkErrorKind {
    Transport,
    Rejected,
    InvalidResponse,
    /// Use only when the SDK guarantees that retrying this operation is safe.
    Retryable,
}

/// Adapter errors carry a category and numeric code, never raw SDK bodies/URLs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SdkError {
    pub kind: SdkErrorKind,
    pub code: Option<i64>,
}

impl SdkError {
    pub fn new(kind: SdkErrorKind, code: Option<i64>) -> Self {
        Self { kind, code }
    }
}
impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SDK error {:?}", self.kind)?;
        if let Some(code) = self.code {
            write!(f, " (code {code})")?;
        }
        Ok(())
    }
}
impl std::error::Error for SdkError {}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    InvalidConfig(&'static str),
    ChannelNotConfigured(Channel),
    InvalidChallenge,
    InvalidGrant,
    InvalidTokens,
    ChannelMismatch,
    InvalidState(LoginState),
    PollTooSoon { retry_after: Duration },
    Sdk(SdkError),
}
impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(field) => write!(f, "Invalid public configuration field: {field}"),
            Self::ChannelNotConfigured(channel) => {
                write!(f, "Channel {channel:?} is not configured")
            }
            Self::InvalidChallenge => f.write_str("SDK returned an invalid QR challenge"),
            Self::InvalidGrant => f.write_str("SDK returned an empty authorization grant"),
            Self::InvalidTokens => f.write_str("SDK returned empty identity or token"),
            Self::ChannelMismatch => f.write_str("SDK token channel does not match this session"),
            Self::InvalidState(state) => write!(f, "Operation is not valid in state {state:?}"),
            Self::PollTooSoon { retry_after } => {
                write!(f, "Poll again after {} ms", retry_after.as_millis())
            }
            Self::Sdk(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for LoginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sdk(error) => Some(error),
            _ => None,
        }
    }
}
impl From<SdkError> for LoginError {
    fn from(value: SdkError) -> Self {
        Self::Sdk(value)
    }
}
