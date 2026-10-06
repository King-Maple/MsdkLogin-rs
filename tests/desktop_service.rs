use msdk_login::{http::LoginService, *};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Notify;

struct Provider {
    entered: Notify,
    release: Notify,
    block: bool,
}
impl QrProvider for Provider {
    fn begin<'a>(&'a self, _: &'a AppConfig, _: Channel) -> SdkFuture<'a, ProviderChallenge> {
        Box::pin(async {
            Ok(ProviderChallenge {
                handle: SecretString::new("fixture"),
                image_png: vec![0xff, 0xd8, 0xff, 0xe0],
                expires_in: Duration::from_secs(60),
                poll_interval: Duration::from_millis(1),
            })
        })
    }
    fn poll<'a>(&'a self, _: &'a SecretString) -> SdkFuture<'a, ScanEvent> {
        Box::pin(async move {
            self.entered.notify_one();
            if self.block {
                self.release.notified().await;
            }
            Ok(ScanEvent::Authorized(SecretString::new("grant")))
        })
    }
    fn cancel<'a>(&'a self, _: &'a SecretString) -> SdkFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
struct Exchange {
    calls: AtomicUsize,
    kind: Option<SdkErrorKind>,
    entered: Notify,
    block: bool,
}
impl MsdkExchanger for Exchange {
    fn exchange<'a>(
        &'a self,
        _: &'a AppConfig,
        channel: Channel,
        _: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            if self.block {
                std::future::pending::<()>().await;
            }
            if let Some(kind) = self.kind {
                Err(SdkError::new(kind, None))
            } else {
                Ok(AuthTokens::new("account", "private-token", channel))
            }
        })
    }
}
fn fixture(
    block_poll: bool,
    kind: Option<SdkErrorKind>,
    block_exchange: bool,
) -> (
    Arc<LoginService<Provider, Exchange>>,
    Arc<Provider>,
    Arc<Exchange>,
) {
    let p = Arc::new(Provider {
        entered: Notify::new(),
        release: Notify::new(),
        block: block_poll,
    });
    let e = Arc::new(Exchange {
        calls: AtomicUsize::new(0),
        kind,
        entered: Notify::new(),
        block: block_exchange,
    });
    let config = AppConfig {
        profile_name: "test".into(),
        msdk_game_id: "123".into(),
        sdk_version: None,
        channel_dis: None,
        qq_app_id: Some("456".into()),
        wechat_app_id: None,
    };
    (
        Arc::new(LoginService::with_adapters(config, p.clone(), e.clone()).unwrap()),
        p,
        e,
    )
}

#[tokio::test]
async fn desktop_contract_confirms_once_and_keeps_credentials_in_backend() {
    let (service, _, exchange) = fixture(false, None, false);
    let qr = service.get_qrcode(Channel::Qq).await.unwrap();
    assert!(qr.qr_image.starts_with("data:image/jpeg;base64,"));
    assert_eq!(service.poll(&qr.id).await.unwrap().status, "confirmed");
    assert_eq!(service.poll(&qr.id).await.unwrap().status, "confirmed");
    assert_eq!(exchange.calls.load(Ordering::Relaxed), 1);
    let json = serde_json::to_string(&service.poll(&qr.id).await.unwrap()).unwrap();
    assert!(!json.contains("private-token"));
    assert_eq!(
        service.get_result(&qr.id).await.unwrap().token,
        "private-token"
    );
    service.cancel(&qr.id).await;
    assert!(service.get_result(&qr.id).await.is_none());
    assert!(service.poll(&qr.id).await.is_err());
}

#[tokio::test]
async fn cancellation_of_inflight_poll_does_not_wait_or_exchange() {
    let (service, provider, exchange) = fixture(true, None, false);
    let qr = service.get_qrcode(Channel::Qq).await.unwrap();
    let task_service = service.clone();
    let id = qr.id.clone();
    let poll = tokio::spawn(async move { task_service.poll(&id).await });
    provider.entered.notified().await;
    tokio::time::timeout(Duration::from_millis(100), service.cancel(&qr.id))
        .await
        .unwrap();
    provider.release.notify_one();
    assert!(poll.await.unwrap().is_err());
    assert_eq!(exchange.calls.load(Ordering::Relaxed), 0);
    assert!(service.get_result(&qr.id).await.is_none());
}

#[tokio::test]
async fn dropped_exchange_does_not_hang_or_retry_from_the_ui() {
    let (service, _, exchange) = fixture(false, None, true);
    let qr = service.get_qrcode(Channel::Qq).await.unwrap();
    let task_service = service.clone();
    let id = qr.id.clone();
    let poll = tokio::spawn(async move { task_service.poll(&id).await });
    exchange.entered.notified().await;
    poll.abort();
    let _ = poll.await;
    assert_eq!(service.poll(&qr.id).await.unwrap().status, "error");
    assert_eq!(service.retry(&qr.id).await.unwrap().status, "error");
    assert_eq!(exchange.calls.load(Ordering::Relaxed), 1);
    assert!(service.get_result(&qr.id).await.is_none());
}

#[tokio::test]
async fn only_explicitly_retryable_failures_can_be_redeemed_again() {
    for (kind, status, calls) in [
        (SdkErrorKind::Transport, "error", 1),
        (SdkErrorKind::Rejected, "rejected", 1),
        (SdkErrorKind::Retryable, "exchange_error", 2),
    ] {
        let (service, _, exchange) = fixture(false, Some(kind), false);
        let qr = service.get_qrcode(Channel::Qq).await.unwrap();
        assert_eq!(service.poll(&qr.id).await.unwrap().status, status);
        assert_eq!(service.poll(&qr.id).await.unwrap().status, status);
        assert_eq!(exchange.calls.load(Ordering::Relaxed), 1);
        assert_eq!(service.retry(&qr.id).await.unwrap().status, status);
        assert_eq!(exchange.calls.load(Ordering::Relaxed), calls);
    }
}

#[tokio::test]
async fn uncertain_sessions_are_pruned_when_a_new_scan_starts() {
    let (service, _, _) = fixture(false, Some(SdkErrorKind::Transport), false);
    for _ in 0..65 {
        let qr = service.get_qrcode(Channel::Qq).await.unwrap();
        assert_eq!(service.poll(&qr.id).await.unwrap().status, "error");
    }
}
