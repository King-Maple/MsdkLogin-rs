//! Offline state-machine demonstration. These adapters never call a login service.
use msdk_login::*;
use std::{sync::Arc, time::Duration};

struct OfflineQr;
impl QrProvider for OfflineQr {
    fn begin<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
    ) -> SdkFuture<'a, ProviderChallenge> {
        Box::pin(async move {
            Ok(ProviderChallenge {
                handle: SecretString::new(format!("offline:{}:{channel:?}", config.profile_name)),
                // Deliberately a synthetic header fixture, NOT a scannable image.
                image_png: b"\x89PNG\r\n\x1a\nOFFLINE_FIXTURE".to_vec(),
                expires_in: Duration::from_secs(60),
                poll_interval: Duration::from_secs(1),
            })
        })
    }
    fn poll<'a>(&'a self, handle: &'a SecretString) -> SdkFuture<'a, ScanEvent> {
        Box::pin(async move {
            Ok(ScanEvent::Authorized(SecretString::new(format!(
                "grant:{}",
                handle.expose_secret()
            ))))
        })
    }
    fn cancel<'a>(&'a self, _: &'a SecretString) -> SdkFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

struct OfflineMsdk;
impl MsdkExchanger for OfflineMsdk {
    fn exchange<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
        _: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens> {
        Box::pin(async move {
            Ok(AuthTokens::new(
                "offline-account",
                format!("offline-token-{}", config.profile_name),
                channel,
            ))
        })
    }
}

fn profile(name: &str) -> AppConfig {
    AppConfig {
        profile_name: name.into(),
        msdk_game_id: format!("demo-{name}"),
        sdk_version: Some("demo-sdk".into()),
        channel_dis: None,
        qq_app_id: Some(format!("demo-qq-{name}")),
        wechat_app_id: Some(format!("demo-wx-{name}")),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("OFFLINE DEMO: synthetic grants/tokens; no QR login or network requests.");
    let qr = Arc::new(OfflineQr);
    let msdk = Arc::new(OfflineMsdk);
    for (name, channel) in [("project-a", Channel::Qq), ("project-b", Channel::Wechat)] {
        let client = LoginClient::new(profile(name), Arc::clone(&qr), Arc::clone(&msdk))?;
        let mut session = client.begin(channel).await?;
        println!("{name}: {:?}", session.state());
        if session.poll().await? == LoginState::Authorized {
            session.exchange().await?;
        }
        println!(
            "{name}: {:?}, credentials={:?}",
            session.state(),
            session.take_tokens()
        );
    }
    Ok(())
}
