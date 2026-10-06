use super::{config::MsdkConfig, transport::HttpAdapter, wire::qr_data_uri};
use crate::{
    AppConfig, Channel, LoginClient, LoginError, LoginSession, LoginState, MsdkExchanger,
    QrProvider,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

/// Backend-only result. Never send this type through a desktop command response.
#[derive(Clone)]
pub struct MsdkCredentials {
    pub openid: String,
    pub token: String,
    pub channel_id: u8,
}
impl MsdkCredentials {
    /// Transfer credentials to the game transport without retaining a copy here.
    pub fn into_parts(mut self) -> (String, String, u8) {
        (
            std::mem::take(&mut self.openid),
            std::mem::take(&mut self.token),
            self.channel_id,
        )
    }
}
impl Drop for MsdkCredentials {
    fn drop(&mut self) {
        self.openid.zeroize();
        self.token.zeroize();
    }
}
impl std::fmt::Debug for MsdkCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsdkCredentials")
            .field("credentials", &"[REDACTED]")
            .field("channel_id", &self.channel_id)
            .finish()
    }
}
#[derive(Serialize, Debug)]
pub struct QrStatus {
    pub status: &'static str,
    pub message: Option<String>,
}
#[derive(Serialize)]
pub struct QrChallenge {
    pub id: String,
    pub qr_image: String,
    pub expires_at: u64,
    pub poll_interval_ms: u64,
}

struct EntryData<P: QrProvider, E: MsdkExchanger> {
    session: LoginSession<P, E>,
    account: Option<MsdkCredentials>,
    exchange_failed: bool,
    message: Option<String>,
}
struct Entry<P: QrProvider, E: MsdkExchanger> {
    cancelled: AtomicBool,
    data: Mutex<EntryData<P, E>>,
}

/// Session-ID facade for Tauri, with per-session locking and immediate cancellation.
pub struct LoginService<P: QrProvider, E: MsdkExchanger> {
    client: LoginClient<P, E>,
    sessions: Mutex<HashMap<String, Arc<Entry<P, E>>>>,
}
pub type QrLoginService = LoginService<HttpAdapter, HttpAdapter>;

impl QrLoginService {
    pub fn new(config: MsdkConfig) -> Result<Self, String> {
        let adapter = Arc::new(HttpAdapter::new(config).map_err(|e| e.to_string())?);
        Self::with_adapters(adapter.app_config(), adapter.clone(), adapter)
            .map_err(|e| e.to_string())
    }
}

impl<P: QrProvider, E: MsdkExchanger> LoginService<P, E> {
    pub fn with_adapters(
        config: AppConfig,
        provider: Arc<P>,
        exchanger: Arc<E>,
    ) -> Result<Self, LoginError> {
        Ok(Self {
            client: LoginClient::new(config, provider, exchanger)?,
            sessions: Mutex::new(HashMap::new()),
        })
    }
    pub async fn begin(&self, channel: &str) -> Result<QrChallenge, String> {
        let channel = match channel {
            "qq" => Channel::Qq,
            "wechat" => Channel::Wechat,
            _ => return Err("不支持的登录方式".into()),
        };
        self.get_qrcode(channel).await
    }

    /// Obtain a QR image and session ID for one configured channel.
    pub async fn get_qrcode(&self, channel: Channel) -> Result<QrChallenge, String> {
        let session = self.client.begin(channel).await.map_err(public_error)?;
        let qr_image = qr_data_uri(session.image_png())?;
        let expires_at = SystemTime::now()
            .checked_add(session.remaining_lifetime())
            .unwrap_or(SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let poll_interval_ms = session.poll_interval().as_millis().min(u64::MAX as u128) as u64;
        let id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, entry| {
            if entry.cancelled.load(Ordering::Acquire) {
                return false;
            }
            match entry.data.try_lock() {
                Ok(mut data) => !matches!(
                    data.session.state(),
                    LoginState::Expired
                        | LoginState::Rejected
                        | LoginState::Failed
                        | LoginState::Cancelled
                        | LoginState::ExchangeUncertain
                ),
                Err(_) => true,
            }
        });
        if sessions.len() >= 64 {
            return Err("扫码会话过多，请先取消不用的会话".into());
        }
        sessions.insert(
            id.clone(),
            Arc::new(Entry {
                cancelled: AtomicBool::new(false),
                data: Mutex::new(EntryData {
                    session,
                    account: None,
                    exchange_failed: false,
                    message: None,
                }),
            }),
        );
        Ok(QrChallenge {
            id,
            qr_image,
            expires_at,
            poll_interval_ms,
        })
    }
    pub async fn cancel(&self, id: &str) {
        let entry = self.sessions.lock().await.remove(id);
        if let Some(entry) = entry {
            entry.cancelled.store(true, Ordering::Release);
            // A pending operation owns its temporary data until completion/drop;
            // the tombstone prevents publishing its late result or taking tokens.
            if let Ok(mut data) = entry.data.try_lock() {
                data.account = None;
                let _ = data.session.cancel().await;
            };
        }
    }
    pub async fn poll(&self, id: &str) -> Result<QrStatus, String> {
        self.advance(id, false).await
    }
    pub async fn retry(&self, id: &str) -> Result<QrStatus, String> {
        self.advance(id, true).await
    }

    async fn entry(&self, id: &str) -> Result<Arc<Entry<P, E>>, String> {
        self.sessions
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| "扫码会话不存在或已取消".into())
    }
    async fn advance(&self, id: &str, retry: bool) -> Result<QrStatus, String> {
        let entry = self.entry(id).await?;
        let mut data = entry.data.lock().await;
        if entry.cancelled.load(Ordering::Acquire) {
            return Err("扫码会话已取消".into());
        }
        match data.session.poll().await {
            Ok(_) | Err(LoginError::PollTooSoon { .. }) => {}
            Err(error) => return Err(public_error(error)),
        }
        // Check cancellation between polling and consuming a one-time grant.
        if entry.cancelled.load(Ordering::Acquire) {
            return Err("扫码会话已取消".into());
        }
        if data.session.state() == LoginState::Authorized && (!data.exchange_failed || retry) {
            match data.session.exchange().await {
                Ok(_) => {
                    data.message = None;
                    data.exchange_failed = false;
                }
                Err(error) => {
                    data.message = Some(public_error(error));
                    data.exchange_failed = true;
                }
            }
        }
        if entry.cancelled.load(Ordering::Acquire) {
            data.account = None;
            let _ = data.session.cancel().await;
            return Err("扫码会话已取消".into());
        }
        if let Some(tokens) = data.session.take_tokens() {
            data.account = Some(MsdkCredentials {
                openid: tokens.subject.expose_secret().to_owned(),
                token: tokens.access_token.expose_secret().to_owned(),
                channel_id: match tokens.channel {
                    Channel::Wechat => 1,
                    Channel::Qq => 2,
                },
            });
        }
        let status = match data.session.state() {
            LoginState::AwaitingScan => "waiting",
            LoginState::Scanned => "scanned",
            LoginState::Authorized => "exchange_error",
            LoginState::Authenticated => "confirmed",
            LoginState::Expired => "expired",
            LoginState::Rejected => "rejected",
            LoginState::Cancelled => "rejected",
            LoginState::Failed | LoginState::ExchangeUncertain => "error",
        };
        if data.session.state() == LoginState::ExchangeUncertain {
            data.message = Some("登录请求结果未确认，请重新获取二维码后扫码".into());
        }
        Ok(QrStatus {
            status,
            message: data.message.clone(),
        })
    }
    /// Read cached credentials after confirmation; no network request is made.
    /// The result remains available for reconnect until the session is cancelled.
    pub async fn get_result(&self, id: &str) -> Option<MsdkCredentials> {
        let entry = self.entry(id).await.ok()?;
        let data = entry.data.lock().await;
        if entry.cancelled.load(Ordering::Acquire) {
            None
        } else {
            data.account.clone()
        }
    }

    /// Compatibility alias for `get_result`.
    pub async fn authenticated(&self, id: &str) -> Option<MsdkCredentials> {
        self.get_result(id).await
    }
}

fn public_error(error: LoginError) -> String {
    match error {
        LoginError::Sdk(sdk) => match sdk.code {
            Some(code) => format!("登录服务返回码 {code}，请重新扫码"),
            None => match sdk.kind {
                crate::SdkErrorKind::Transport => "登录服务连接失败，请稍后重试".into(),
                crate::SdkErrorKind::Rejected => "登录授权被拒绝，请重新扫码".into(),
                _ => "登录服务响应无效，请重新扫码".into(),
            },
        },
        other => other.to_string(),
    }
}
