use msdk_login::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

fn config(profile: &str) -> AppConfig {
    AppConfig {
        profile_name: profile.into(),
        msdk_game_id: format!("demo-{profile}"),
        sdk_version: Some("demo-sdk".into()),
        channel_dis: None,
        qq_app_id: Some(format!("qq-{profile}")),
        wechat_app_id: Some(format!("wx-{profile}")),
    }
}

struct LocalProvider {
    events: Mutex<VecDeque<ScanEvent>>,
    profiles: Mutex<Vec<String>>,
    poll_count: Mutex<usize>,
    expires_in: Duration,
    interval: Duration,
    cancel_fails: bool,
    cancel_pending: bool,
    poll_delay: Duration,
    image: Vec<u8>,
}

impl LocalProvider {
    fn new(events: Vec<ScanEvent>) -> Self {
        Self {
            events: Mutex::new(events.into()),
            profiles: Mutex::new(vec![]),
            poll_count: Mutex::new(0),
            expires_in: Duration::from_secs(300),
            interval: Duration::from_nanos(1),
            cancel_fails: false,
            cancel_pending: false,
            poll_delay: Duration::ZERO,
            image: b"\x89PNG\r\n\x1a\nfixture".to_vec(),
        }
    }
}

impl QrProvider for LocalProvider {
    fn begin<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
    ) -> SdkFuture<'a, ProviderChallenge> {
        Box::pin(async move {
            self.profiles.lock().unwrap().push(format!(
                "{}:{}",
                config.msdk_game_id,
                config.app_id(channel).unwrap()
            ));
            Ok(ProviderChallenge {
                handle: SecretString::new("test-handle"),
                image_png: self.image.clone(),
                expires_in: self.expires_in,
                poll_interval: self.interval,
            })
        })
    }
    fn poll<'a>(&'a self, _: &'a SecretString) -> SdkFuture<'a, ScanEvent> {
        Box::pin(async move {
            *self.poll_count.lock().unwrap() += 1;
            if !self.poll_delay.is_zero() {
                tokio::time::sleep(self.poll_delay).await;
            }
            Ok(self
                .events
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(ScanEvent::Waiting))
        })
    }
    fn cancel<'a>(&'a self, _: &'a SecretString) -> SdkFuture<'a, ()> {
        Box::pin(async move {
            if self.cancel_pending {
                std::future::pending::<()>().await;
            }
            if self.cancel_fails {
                Err(SdkError::new(SdkErrorKind::Transport, Some(9)))
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Default)]
struct LocalExchange {
    attempts: Mutex<Vec<String>>,
    fail_once: Mutex<bool>,
}
impl MsdkExchanger for LocalExchange {
    fn exchange<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
        _: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens> {
        Box::pin(async move {
            self.attempts
                .lock()
                .unwrap()
                .push(config.msdk_game_id.clone());
            if std::mem::take(&mut *self.fail_once.lock().unwrap()) {
                return Err(SdkError::new(SdkErrorKind::Retryable, Some(42)));
            }
            Ok(AuthTokens::new(
                "synthetic-subject",
                format!("token-{}", config.profile_name),
                channel,
            ))
        })
    }
}

#[tokio::test]
async fn confirmation_and_exchange_are_separate_and_tokens_are_taken_once() {
    let provider = Arc::new(LocalProvider::new(vec![
        ScanEvent::Scanned,
        ScanEvent::Authorized(SecretString::new("grant")),
    ]));
    let exchange = Arc::new(LocalExchange::default());
    let client = LoginClient::new(config("a"), provider, exchange.clone()).unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    assert_eq!(session.poll().await.unwrap(), LoginState::Scanned);
    assert_eq!(session.poll().await.unwrap(), LoginState::Authorized);
    assert!(exchange.attempts.lock().unwrap().is_empty());
    assert!(session.take_tokens().is_none());
    assert_eq!(session.exchange().await.unwrap(), LoginState::Authenticated);
    assert_eq!(
        session.take_tokens().unwrap().access_token.expose_secret(),
        "token-a"
    );
    assert!(session.take_tokens().is_none());
    assert_eq!(session.poll().await.unwrap(), LoginState::Authenticated);
    assert!(session.exchange().await.is_err());
}

#[tokio::test]
async fn profiles_remain_bound_to_their_own_sessions() {
    let provider = Arc::new(LocalProvider::new(vec![
        ScanEvent::Authorized(SecretString::new("a")),
        ScanEvent::Authorized(SecretString::new("b")),
    ]));
    let exchange = Arc::new(LocalExchange::default());
    let a = LoginClient::new(config("one"), provider.clone(), exchange.clone()).unwrap();
    let b = LoginClient::new(config("two"), provider.clone(), exchange.clone()).unwrap();
    let mut first = a.begin(Channel::Qq).await.unwrap();
    let mut second = b.begin(Channel::Wechat).await.unwrap();
    first.poll().await.unwrap();
    second.poll().await.unwrap();
    second.exchange().await.unwrap();
    first.exchange().await.unwrap();
    assert_eq!(
        *provider.profiles.lock().unwrap(),
        ["demo-one:qq-one", "demo-two:wx-two"]
    );
    assert_eq!(*exchange.attempts.lock().unwrap(), ["demo-two", "demo-one"]);
    assert_eq!(
        first.take_tokens().unwrap().access_token.expose_secret(),
        "token-one"
    );
    assert_eq!(
        second.take_tokens().unwrap().access_token.expose_secret(),
        "token-two"
    );
}

#[tokio::test]
async fn cancellation_removes_tokens_even_when_adapter_cancel_fails() {
    let mut provider = LocalProvider::new(vec![ScanEvent::Authorized(SecretString::new("grant"))]);
    provider.cancel_fails = true;
    let client = LoginClient::new(
        config("a"),
        Arc::new(provider),
        Arc::new(LocalExchange::default()),
    )
    .unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    session.poll().await.unwrap();
    session.exchange().await.unwrap();
    assert!(session.cancel().await.is_err());
    assert_eq!(session.state(), LoginState::Cancelled);
    assert!(session.take_tokens().is_none());
    assert_eq!(session.poll().await.unwrap(), LoginState::Cancelled);
}

#[tokio::test]
async fn retries_require_an_explicit_adapter_signal_and_caller_action() {
    let provider = Arc::new(LocalProvider::new(vec![ScanEvent::Authorized(
        SecretString::new("grant"),
    )]));
    let exchange = Arc::new(LocalExchange::default());
    *exchange.fail_once.lock().unwrap() = true;
    let client = LoginClient::new(config("a"), provider, exchange.clone()).unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    session.poll().await.unwrap();
    assert!(session.exchange().await.is_err());
    assert_eq!(session.state(), LoginState::Authorized);
    assert_eq!(session.poll().await.unwrap(), LoginState::Authorized);
    assert_eq!(exchange.attempts.lock().unwrap().len(), 1);
    session.exchange().await.unwrap();
    assert_eq!(exchange.attempts.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn polling_is_throttled_and_expiration_does_not_contact_provider() {
    let mut provider = LocalProvider::new(vec![ScanEvent::Waiting]);
    provider.interval = Duration::from_secs(60);
    let provider = Arc::new(provider);
    let client = LoginClient::new(
        config("a"),
        provider.clone(),
        Arc::new(LocalExchange::default()),
    )
    .unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    session.poll().await.unwrap();
    assert!(matches!(
        session.poll().await,
        Err(LoginError::PollTooSoon { .. })
    ));
    assert_eq!(*provider.poll_count.lock().unwrap(), 1);
    let mut provider = LocalProvider::new(vec![]);
    provider.expires_in = Duration::from_millis(1);
    let provider = Arc::new(provider);
    let client = LoginClient::new(
        config("a"),
        provider.clone(),
        Arc::new(LocalExchange::default()),
    )
    .unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(session.poll().await.unwrap(), LoginState::Expired);
    assert_eq!(*provider.poll_count.lock().unwrap(), 0);
}

#[test]
fn secret_debug_is_redacted_and_public_config_rejects_unknown_secret_fields() {
    let secret = SecretString::new("sensitive-fixture-value");
    assert!(!format!("{secret:?}").contains("sensitive-fixture-value"));
    let tokens = AuthTokens::new("sensitive-subject", "sensitive-token", Channel::Qq);
    assert!(!format!("{tokens:?}").contains("sensitive-subject"));
    assert!(!format!("{tokens:?}").contains("sensitive-token"));
    let challenge = ProviderChallenge {
        handle: SecretString::new("private-handle"),
        image_png: b"private-image-data".to_vec(),
        expires_in: Duration::from_secs(30),
        poll_interval: Duration::from_secs(1),
    };
    assert!(!format!("{challenge:?}").contains("private-handle"));
    assert!(!format!("{challenge:?}").contains("private-image-data"));
    let mut value = serde_json::to_value(config("a")).unwrap();
    value["sdk_key"] = serde_json::json!("must-not-be-a-public-field");
    assert!(serde_json::from_value::<AppConfig>(value).is_err());
}

#[tokio::test]
async fn unavailable_channels_and_invalid_configs_fail_before_sdk_calls() {
    let provider = Arc::new(LocalProvider::new(vec![]));
    let mut cfg = config("a");
    cfg.wechat_app_id = None;
    let client =
        LoginClient::new(cfg, provider.clone(), Arc::new(LocalExchange::default())).unwrap();
    assert!(matches!(
        client.begin(Channel::Wechat).await,
        Err(LoginError::ChannelNotConfigured(Channel::Wechat))
    ));
    assert!(provider.profiles.lock().unwrap().is_empty());
    let mut cfg = config("a");
    cfg.msdk_game_id.clear();
    assert!(LoginClient::new(cfg, provider, Arc::new(LocalExchange::default())).is_err());
}

struct InterruptedExchange;
impl MsdkExchanger for InterruptedExchange {
    fn exchange<'a>(
        &'a self,
        _: &'a AppConfig,
        _: Channel,
        _: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn dropped_exchange_is_uncertain_and_cannot_silently_redeem_twice() {
    let provider = Arc::new(LocalProvider::new(vec![ScanEvent::Authorized(
        SecretString::new("grant"),
    )]));
    let client = LoginClient::new(config("a"), provider, Arc::new(InterruptedExchange)).unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    session.poll().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), session.exchange())
            .await
            .is_err()
    );
    assert_eq!(session.state(), LoginState::ExchangeUncertain);
    assert!(session.exchange().await.is_err());
    session.cancel().await.unwrap();
    assert_eq!(session.state(), LoginState::Cancelled);
}

struct FixedExchange(Mutex<Option<Result<AuthTokens, SdkError>>>);
impl MsdkExchanger for FixedExchange {
    fn exchange<'a>(
        &'a self,
        _: &'a AppConfig,
        _: Channel,
        _: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap()
                .take()
                .expect("must exchange only once")
        })
    }
}

#[tokio::test]
async fn invalid_or_uncertain_exchange_results_never_expose_tokens_or_retry() {
    let transport = SdkError::new(SdkErrorKind::Transport, None);
    for (result, error, state) in [
        (
            Ok(AuthTokens::new("account", "token", Channel::Wechat)),
            LoginError::ChannelMismatch,
            LoginState::Failed,
        ),
        (
            Ok(AuthTokens::new("", "token", Channel::Qq)),
            LoginError::InvalidTokens,
            LoginState::Failed,
        ),
        (
            Ok(AuthTokens::new("account", "  ", Channel::Qq)),
            LoginError::InvalidTokens,
            LoginState::Failed,
        ),
        (
            Err(transport),
            LoginError::Sdk(transport),
            LoginState::ExchangeUncertain,
        ),
    ] {
        let provider = Arc::new(LocalProvider::new(vec![ScanEvent::Authorized(
            SecretString::new("grant"),
        )]));
        let exchange = Arc::new(FixedExchange(Mutex::new(Some(result))));
        let client = LoginClient::new(config("a"), provider.clone(), exchange).unwrap();
        let mut session = client.begin(Channel::Qq).await.unwrap();
        session.poll().await.unwrap();
        assert_eq!(session.exchange().await.unwrap_err(), error);
        assert_eq!(session.state(), state);
        assert!(session.take_tokens().is_none());
        assert!(session.image_png().is_empty());
        assert_eq!(session.poll().await.unwrap(), state);
        assert_eq!(*provider.poll_count.lock().unwrap(), 1);
        assert_eq!(
            session.exchange().await,
            Err(LoginError::InvalidState(state))
        );
    }
}

#[tokio::test]
async fn empty_grant_and_rejection_stop_further_polling() {
    for (event, expected) in [
        (
            ScanEvent::Authorized(SecretString::new("")),
            LoginState::Failed,
        ),
        (ScanEvent::Rejected, LoginState::Rejected),
    ] {
        let provider = Arc::new(LocalProvider::new(vec![event]));
        let exchange = Arc::new(LocalExchange::default());
        let client = LoginClient::new(config("a"), provider.clone(), exchange.clone()).unwrap();
        let mut session = client.begin(Channel::Qq).await.unwrap();
        let result = session.poll().await;
        if expected == LoginState::Failed {
            assert_eq!(result, Err(LoginError::InvalidGrant));
        } else {
            assert_eq!(result, Ok(expected));
        }
        assert_eq!(session.poll().await.unwrap(), expected);
        assert_eq!(*provider.poll_count.lock().unwrap(), 1);
        assert!(session.exchange().await.is_err());
        assert!(exchange.attempts.lock().unwrap().is_empty());
        assert!(session.take_tokens().is_none());
    }
}

#[tokio::test]
async fn authorization_arriving_after_deadline_cannot_be_redeemed() {
    let mut provider = LocalProvider::new(vec![ScanEvent::Authorized(SecretString::new("late"))]);
    provider.expires_in = Duration::from_millis(20);
    provider.poll_delay = Duration::from_millis(40);
    let provider = Arc::new(provider);
    let exchange = Arc::new(LocalExchange::default());
    let client = LoginClient::new(config("a"), provider.clone(), exchange.clone()).unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    assert_eq!(session.poll().await.unwrap(), LoginState::Expired);
    assert!(session.exchange().await.is_err());
    assert!(session.image_png().is_empty());
    assert_eq!(*provider.poll_count.lock().unwrap(), 1);
    assert!(exchange.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn dropping_remote_cancellation_still_clears_local_credentials() {
    let mut provider = LocalProvider::new(vec![ScanEvent::Authorized(SecretString::new("grant"))]);
    provider.cancel_pending = true;
    let exchange = Arc::new(LocalExchange::default());
    let client = LoginClient::new(config("a"), Arc::new(provider), exchange.clone()).unwrap();
    let mut session = client.begin(Channel::Qq).await.unwrap();
    session.poll().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), session.cancel())
            .await
            .is_err()
    );
    assert_eq!(session.state(), LoginState::Cancelled);
    assert!(session.image_png().is_empty());
    assert!(session.take_tokens().is_none());
    assert!(session.exchange().await.is_err());
    assert!(exchange.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn jpeg_qr_images_are_accepted_but_html_is_rejected() {
    for (image, accepted) in [
        (vec![0xff, 0xd8, 0xff, 0xe0], true),
        (b"<html>error</html>".to_vec(), false),
    ] {
        let mut provider = LocalProvider::new(vec![]);
        provider.image = image;
        let client = LoginClient::new(
            config("a"),
            Arc::new(provider),
            Arc::new(LocalExchange::default()),
        )
        .unwrap();
        assert_eq!(client.begin(Channel::Qq).await.is_ok(), accepted);
    }
}
