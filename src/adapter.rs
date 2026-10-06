use crate::{AppConfig, Channel, SdkError, SecretString};
use std::{fmt, future::Future, pin::Pin, time::Duration};

pub type SdkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SdkError>> + Send + 'a>>;

/// Image bytes are display data; Debug omits both the image and session handle.
pub struct ProviderChallenge {
    pub handle: SecretString,
    /// Legacy field name: accepts PNG, JPEG, GIF and WebP.
    pub image_png: Vec<u8>,
    /// Remaining lifetime when begin returns, not the original server TTL.
    pub expires_in: Duration,
    pub poll_interval: Duration,
}
impl fmt::Debug for ProviderChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderChallenge")
            .field("handle", &self.handle)
            .field("image_bytes", &self.image_png.len())
            .field("expires_in", &self.expires_in)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[derive(Debug)]
pub enum ScanEvent {
    Waiting,
    Scanned,
    Authorized(SecretString),
    Rejected,
    Expired,
}

/// Implement with the application's login provider integration.
/// Handles must uniquely identify the project/channel session. Never return raw
/// SDK diagnostics as a token, handle or public error message.
pub trait QrProvider: Send + Sync + 'static {
    fn begin<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
    ) -> SdkFuture<'a, ProviderChallenge>;
    fn poll<'a>(&'a self, handle: &'a SecretString) -> SdkFuture<'a, ScanEvent>;
    fn cancel<'a>(&'a self, handle: &'a SecretString) -> SdkFuture<'a, ()>;
}

#[derive(Debug)]
pub struct AuthTokens {
    pub subject: SecretString,
    pub access_token: SecretString,
    pub channel: Channel,
}
impl AuthTokens {
    pub fn new(
        subject: impl Into<String>,
        access_token: impl Into<String>,
        channel: Channel,
    ) -> Self {
        Self {
            subject: SecretString::new(subject),
            access_token: SecretString::new(access_token),
            channel,
        }
    }
}

/// Bind the grant to this exact config/channel before redeeming it.
/// Only return Retryable if redemption definitely did not occur (or the SDK
/// supplies an idempotency guarantee). An ambiguous timeout is Transport.
pub trait MsdkExchanger: Send + Sync + 'static {
    fn exchange<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
        grant: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens>;
}
