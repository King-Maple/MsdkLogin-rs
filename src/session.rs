use crate::{
    AppConfig, AuthTokens, Channel, LoginError, MsdkExchanger, QrProvider, ScanEvent, SdkErrorKind,
    SecretString,
};
use serde::Serialize;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginState {
    AwaitingScan,
    Scanned,
    Authorized,
    Authenticated,
    Rejected,
    Expired,
    Cancelled,
    Failed,
    ExchangeUncertain,
}

pub struct LoginClient<P: QrProvider + ?Sized, E: MsdkExchanger + ?Sized> {
    config: Arc<AppConfig>,
    provider: Arc<P>,
    exchanger: Arc<E>,
}

impl<P: QrProvider + ?Sized, E: MsdkExchanger + ?Sized> LoginClient<P, E> {
    pub fn new(config: AppConfig, provider: Arc<P>, exchanger: Arc<E>) -> Result<Self, LoginError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            provider,
            exchanger,
        })
    }

    pub async fn begin(&self, channel: Channel) -> Result<LoginSession<P, E>, LoginError> {
        self.config.app_id(channel)?;
        let challenge = self.provider.begin(&self.config, channel).await?;
        let deadline = Instant::now().checked_add(challenge.expires_in);
        if challenge.handle.is_empty()
            || challenge.expires_in.is_zero()
            || challenge.poll_interval.is_zero()
            || challenge.image_png.len() > 2 * 1024 * 1024
            || crate::image::image_mime(&challenge.image_png).is_none()
            || deadline.is_none()
        {
            return Err(LoginError::InvalidChallenge);
        }
        Ok(LoginSession {
            config: Arc::clone(&self.config),
            provider: Arc::clone(&self.provider),
            exchanger: Arc::clone(&self.exchanger),
            channel,
            handle: challenge.handle,
            image_png: challenge.image_png,
            deadline: deadline.expect("validated deadline"),
            interval: challenge.poll_interval,
            next_poll: None,
            state: LoginState::AwaitingScan,
            grant: None,
            tokens: None,
        })
    }
}

/// Keep sessions in the Rust backend. &mut methods prevent overlapping operations.
pub struct LoginSession<P: QrProvider + ?Sized, E: MsdkExchanger + ?Sized> {
    config: Arc<AppConfig>,
    provider: Arc<P>,
    exchanger: Arc<E>,
    channel: Channel,
    handle: SecretString,
    image_png: Vec<u8>,
    deadline: Instant,
    interval: Duration,
    next_poll: Option<Instant>,
    state: LoginState,
    grant: Option<SecretString>,
    tokens: Option<AuthTokens>,
}
impl<P: QrProvider + ?Sized, E: MsdkExchanger + ?Sized> fmt::Debug for LoginSession<P, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("channel", &self.channel)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<P: QrProvider + ?Sized, E: MsdkExchanger + ?Sized> LoginSession<P, E> {
    pub fn image_png(&self) -> &[u8] {
        &self.image_png
    }
    /// Original bytes, which may be PNG, JPEG, GIF or WebP.
    pub fn image_bytes(&self) -> &[u8] {
        &self.image_png
    }
    pub fn poll_interval(&self) -> Duration {
        self.interval
    }
    pub fn remaining_lifetime(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
    pub fn state(&mut self) -> LoginState {
        self.expire();
        self.state
    }
    pub fn take_tokens(&mut self) -> Option<AuthTokens> {
        self.tokens.take()
    }

    fn expire(&mut self) {
        if matches!(
            self.state,
            LoginState::AwaitingScan | LoginState::Scanned | LoginState::Authorized
        ) && Instant::now() >= self.deadline
        {
            self.finish(LoginState::Expired);
        }
    }

    fn finish(&mut self, state: LoginState) {
        self.state = state;
        self.grant = None;
        self.tokens = None;
        self.image_png.zeroize();
    }

    /// Returns the current terminal/authorized state without another SDK request.
    pub async fn poll(&mut self) -> Result<LoginState, LoginError> {
        self.expire();
        if !matches!(self.state, LoginState::AwaitingScan | LoginState::Scanned) {
            return Ok(self.state);
        }
        let now = Instant::now();
        if let Some(next) = self.next_poll.filter(|next| *next > now) {
            return Err(LoginError::PollTooSoon {
                retry_after: next.duration_since(now),
            });
        }
        self.next_poll = Some(now.checked_add(self.interval).unwrap_or(self.deadline));
        let event = self.provider.poll(&self.handle).await;
        self.expire();
        if self.state == LoginState::Expired {
            return Ok(self.state);
        }
        match event {
            Ok(ScanEvent::Waiting) => {} // A late waiting event must not undo Scanned.
            Ok(ScanEvent::Scanned) => self.state = LoginState::Scanned,
            Ok(ScanEvent::Authorized(grant)) if !grant.is_empty() => {
                self.grant = Some(grant);
                self.state = LoginState::Authorized;
            }
            Ok(ScanEvent::Authorized(_)) => {
                self.finish(LoginState::Failed);
                return Err(LoginError::InvalidGrant);
            }
            Ok(ScanEvent::Rejected) => self.finish(LoginState::Rejected),
            Ok(ScanEvent::Expired) => self.finish(LoginState::Expired),
            Err(error) => {
                if error.kind == SdkErrorKind::Rejected {
                    self.finish(LoginState::Rejected);
                }
                if error.kind == SdkErrorKind::InvalidResponse {
                    self.finish(LoginState::Failed);
                }
                return Err(error.into());
            }
        }
        Ok(self.state)
    }

    /// Explicit redemption. A dropped future or uncertain transport result cannot
    /// be blindly retried; cancel/start a new flow or reconcile in the official SDK.
    pub async fn exchange(&mut self) -> Result<LoginState, LoginError> {
        self.expire();
        if self.state != LoginState::Authorized {
            return Err(LoginError::InvalidState(self.state));
        }
        self.state = LoginState::ExchangeUncertain;
        // Own the grant in this future so cancellation drops and zeroizes it.
        let grant = self.grant.take().ok_or(LoginError::InvalidGrant)?;
        let result = self
            .exchanger
            .exchange(&self.config, self.channel, &grant)
            .await;
        match result {
            Ok(tokens) => {
                if tokens.channel != self.channel {
                    self.finish(LoginState::Failed);
                    return Err(LoginError::ChannelMismatch);
                }
                if tokens.subject.is_empty() || tokens.access_token.is_empty() {
                    self.finish(LoginState::Failed);
                    return Err(LoginError::InvalidTokens);
                }
                self.finish(LoginState::Authenticated);
                self.tokens = Some(tokens);
            }
            Err(error) => {
                match error.kind {
                    SdkErrorKind::Retryable => {
                        self.grant = Some(grant);
                        self.state = LoginState::Authorized;
                        self.expire();
                    }
                    SdkErrorKind::Rejected => self.finish(LoginState::Rejected),
                    SdkErrorKind::InvalidResponse => self.finish(LoginState::Failed),
                    SdkErrorKind::Transport => self.finish(LoginState::ExchangeUncertain),
                }
                return Err(error.into());
            }
        }
        Ok(self.state)
    }

    /// Local cancellation always happens first. This is not an access-token logout.
    pub async fn cancel(&mut self) -> Result<(), LoginError> {
        self.finish(LoginState::Cancelled);
        self.provider.cancel(&self.handle).await.map_err(Into::into)
    }
}

impl<P: QrProvider + ?Sized, E: MsdkExchanger + ?Sized> Drop for LoginSession<P, E> {
    fn drop(&mut self) {
        self.image_png.zeroize();
    }
}
